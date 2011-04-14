#!/usr/bin/perl
my $awskeydefault="<yourawskey>";
my $awssecretdefault="<yourawssecret>";

use strict;
use warnings;
use CGI;
use CGI::Carp qw(fatalsToBrowser);
use Net::Amazon::EC2;
use Net::Amazon::S3;
use SimpleDB::Client;
use Crypt::SSLeay;
use File::Temp qw(tempfile);
use Net::SSH qw(ssh_cmd);
use Net::SCP qw(scp);

my $q = CGI->new();
my $AWSKEY = $q->param("AWSKEY") || $awskeydefault || die "Missing mandatory parameter: AWS Access Key";
my $AWSSECRET = $q->param("AWSSECRET") || $awssecretdefault || die "Missing mandatory parameter: AWS Secret Key";
my $S3 = $q->param("S3BUCKET") || undef;

my $AMI = "ami-ca54bea3";

local ($|) = 1;
print $q->header("text/html");

print "<p>Testing Amazon EC2 credentials...";
my $ec2 = Net::Amazon::EC2->new(
       AWSAccessKeyId  => $AWSKEY, 
       SecretAccessKey => $AWSSECRET,
);
my $ecSecurityGroups = $ec2->describe_security_groups();
if (ref($ecSecurityGroups) ne "ARRAY" && $ecSecurityGroups->isa("Net::Amazon::EC2::Errors")) {
    die "Your Amazon keys are incorrect, or you don't have EC2 enabled on your account.  Please double-check your keypair and ensure that EC2 is enabled!";
}
print "ok!</p><p>Testing S3 access...";
my $s3 = Net::Amazon::S3->new(
    {   aws_access_key_id     => $AWSKEY,
        aws_secret_access_key => $AWSSECRET,
        secure                => 1,
    }
);
my $s3Buckets = $s3->buckets;
die "You must enable S3 on your account!  Please enable S3 and try again." unless defined $s3Buckets;
$s3 = Net::Amazon::S3->new(
    {   aws_access_key_id     => $AWSKEY,
        aws_secret_access_key => $AWSSECRET,
        secure                => 1,
        retry                 => 1,
    }
);
print "ok!</p><p>Testing SimpleDB access...";
my $sdb = SimpleDB::Client->new(
        access_key=>$AWSKEY,
        secret_key=>$AWSSECRET
);
my $sdbDomains;
eval {$sdbDomains = $sdb->send_request("ListDomains");};


my $hashref = $sdb->send_request('CreateDomain', {DomainName => 'app_customs'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'apps'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'apps_invalid'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'networks'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'customs'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'customs_invalid'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'stats'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'stats_temp'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'stats_invalid'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'users'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'users_forgot'});
$hashref = $sdb->send_request('CreateDomain', {DomainName => 'users_unverified'});

 
die "You must enable SDB on your account!  Please enable SDB and try again." if $@;

print "ok!</p><p>Going to install a new AdWhirl EC2 instance for you...</p>";
print "<p style='font-weight: bold'>Do NOT leave this screen unless an error is reported or until you get your private key for accessing the new AdWhirl server!</p>";

print "<p>Searching for adwhirl AMI image...";
my $image = $ec2->describe_images(ImageId => $AMI);
die "AMI $AMI can't be found - aborting. (Please update AMI in script from http://code.google.com/p/adwhirl/wiki/ServerInstructions)" unless defined $image && ref($image) ne "Net::Amazon::EC2::Errors";
print "ok!</p>";

print "<p>Testing for adwhirl security group...";
my $adwhirl_group = undef;
foreach my $group (@$ecSecurityGroups) {
    $adwhirl_group = $group if $group->group_name eq "adwhirl_group";
}
if (defined($adwhirl_group)) {
    print "found existing adwhirl security group.</p>";
} else {
    die "Error creating adwhirl security group" unless $ec2->create_security_group(GroupName => "adwhirl_group", "GroupDescription" => "Default security group for Adwhirl instances");
    unless ($ec2->authorize_security_group_ingress(GroupName => "adwhirl_group", IpProtocol => "tcp", FromPort => "22", ToPort => "22", CidrIp => "0.0.0.0/0")) {
        $ec2->delete_security_group(GroupName => "adwhirl_group");
        die "Error adding permissions to port 22.  Can't proceed";
    }
    $ec2->authorize_security_group_ingress(GroupName => "adwhirl_group", IpProtocol => "tcp", FromPort => "80", ToPort => "80", CidrIp => "0.0.0.0/0") || warn "Error adding permissions to port 80 - check your EC2 web panel later";
    $ec2->authorize_security_group_ingress(GroupName => "adwhirl_group", IpProtocol => "tcp", FromPort => "8080", ToPort => "8080", CidrIp => "0.0.0.0/0") || warn "Error adding permissions to port 8080 - check your EC2 web panel later";
    print "created new adwhirl security group</p>";
}
print "<p>Going to generate a new keypair for accessing the Adwhirl server...";
my $keyPairName = "AdWhirl-" . time();
my $keyPair = $ec2->create_key_pair(KeyName => $keyPairName);
print "generated keypair $keyPairName</p>";

print "<p>Booting new instance...";
my $reservationInfo = $ec2->run_instances(
    ImageId => $AMI,
    MinCount => 1,
    MaxCount => 1,
    KeyName => $keyPairName,
    SecurityGroup => "adwhirl_group",
);

die "AMI $AMI can't be started - aborting!" unless defined $reservationInfo && ref($reservationInfo) ne "Net::Amazon::EC2::Errors";
print "Sent start command.  Waiting for instance to boot</p><p style='font-weight: bold'>This may take up to 15 minutes.  DO NOT NAVIGATE AWAY FROM THIS PAGE!</p>";
print "<p>Waiting";
my $runningInstance = $reservationInfo->instances_set->[0];
my $instanceID = $runningInstance->instance_id;
while ($runningInstance->instance_state->name ne "running") {
    sleep(15);
    print ".";
    $reservationInfo = $ec2->describe_instances(InstanceId => $instanceID);
    $runningInstance = $reservationInfo->[0]->instances_set->[0];
}
print "booting...";
sleep(60);
print "ready</p>";
# Write SSH key to disk
my ($sshfh, $sshkey) = tempfile("ec2XXXXXXX", UNLINK => 1);
binmode $sshfh;
print $sshfh $keyPair->key_material();
close $sshfh;
# Write patch file to disk
my ($patchfh, $patchfile) = tempfile("ec2XXXXXXX", UNLINK => 1);
my $patchdata = "";
while (<DATA>) {
    s/PUBLICKEY/$AWSKEY/;
    s/SECRETKEY/$AWSSECRET/;
    s/S3BUCKET/$S3/;
    print $patchfh $_;
    $patchdata .= $_;
}
close $patchfh;
$Net::SCP::scp = "scp -i $sshkey -o 'StrictHostKeyChecking no'";
@Net::SSH::ssh_options = &Net::SSH::_ssh_options;
push @Net::SSH::ssh_options, ('-i', $sshkey, "-o", "StrictHostKeyChecking no");
my $host = 'root@' . $runningInstance->dns_name;
use Fcntl;

sysopen (MYFILE, $keyPairName . '.pem', O_RDWR|O_EXCL|O_CREAT, 0400);
print MYFILE $keyPair->key_material() ;
close (MYFILE);


print "<p>Patching...";
eval {
    #ssh_cmd($host, "rm -rf /root/adwhirl-servers-mobile");
    #ssh_cmd($host, "rm -rf /root/adwhirl-servers-website");
    #ssh_cmd($host, "cd /root/adwhirl-servers && hg clone https://servers-website.adwhirl.googlecode.com/hg/ website && cd /root/adwhirl-servers && hg clone https://servers-mobile.adwhirl.googlecode.com/hg/ mobile");
    ssh_cmd($host, "ls /root");
};



    #svn co a file that takes input sdb key/secret and prints out app names
    scp($patchfile, "$host:");
    ssh_cmd({
        user => 'root',
        host => $runningInstance->dns_name,
        command => 'cd /root/adwhirl-servers-mobile && patch',
        args => [ '-F10', '-p1' ],
        stdin_string => $patchdata,
      } );
      
    #$host, "cd adwhirl-servers && patch -F5 -p0");
    ssh_cmd($host, "chmod 777 /root/adwhirl-servers-website/inc/smarty/templates_c && chmod 777 /root/adwhirl-servers-website/www.adwhirl.com/imagesTemp");
    ssh_cmd($host, "echo 'include_path=.:/root/adwhirl-servers-website/:/root/adwhirl-servers-website/inc/class/amazon-simpledb-2009-04-15-php5-library/src' > /etc/php.d/includes.ini");
    ssh_cmd($host, "mount --bind /root/adwhirl-servers-website /var/www");
    ssh_cmd($host, "ln -s /var/www/www.adwhirl.com/ /var/www/html");
    ssh_cmd($host, "ln -s /var/www/www.adwhirl.com/ /var/www/html/www.adwhirl.com");


    ssh_cmd($host, "/etc/init.d/httpd start");
    ssh_cmd($host, "/etc/init.d/memcached start");
    ssh_cmd($host, "/etc/init.d/atd start");
    ssh_cmd($host, "cd adwhirl-servers-mobile && ant clean && ant dist && mkdir /mnt/adwhirl");
    print "...";
    my $pid = fork();
    if ($pid == 0) {
        eval {ssh_cmd($host, "cd adwhirl-servers-mobile && echo 'nohup java -Xmx512m -cp dist/adwhirl.jar Invoker &' > start.sh && echo 'nohup java -cp dist/adwhirl.jar Daemon &' >> start.sh && chmod a+x start.sh && echo 'sh `pwd`/start.sh' | at now + 1 minutes ");};
        exit(0);
    }    
    #ssh_cmd({
    #    user => 'root',
    #    host => $runningInstance->dns_name,
    #    command => 'at',
    #    args => [ 'now', '+', '1', 'minutes' ],
    #    stdin_string => "cd /root/adwhirl-servers-mobile && nohup java -Xmx512m -cp dist/adwhirl.jar Invoker",
    #  } );
    #ssh_cmd({
    #    user => 'root',
    #    host => $runningInstance->dns_name,
    #    command => 'at',
    #    args => [ 'now', '+', '1', 'minutes' ],
    #    stdin_string => "cd /root/adwhirl-servers-mobile && nohup java -cp dist/adwhirl.jar Daemon",
    #  } );
    #  sleep(90);


print "Done!<br>";

#open (MYFILE, '>>' . $keyPairName);

print "In order to connect to your server via SSH, you'll need the following SSH key:<br><pre>\n" . $keyPair->key_material() ."\n</pre><br><br>";
print "You can now connect to your new server at http://" . $runningInstance->dns_name . ":8080/";
print "The install process is complete.  You can safely leave the page after following the instructions above.";

print "Connect to the server by issuing the following command:\n";
print "ssh -i " . $keyPairName . ".pem root@" . $runningInstance->dns_name;
sleep 10;
kill $pid;
waitpid $pid, 0;
__DATA__
diff -r 22258869aca3 SDBBackup/src/com/admob/Util.java
--- a/SDBBackup/src/com/admob/Util.java Mon May 17 16:00:39 2010 -0700
+++ b/SDBBackup/src/com/admob/Util.java Thu May 27 21:18:21 2010 +0000
@@ -23,8 +23,8 @@
        DOMAINS.add("users");
     }

-    public static final String myAccessKey = "CHANGEME";
-    public static final String mySecretKey = "CHANGEME";
+    public static final String myAccessKey = "PUBLICKEY";
+    public static final String mySecretKey = "SECRETKEY";

     public static AmazonSimpleDB getSDB() {
        return new AmazonSimpleDBClient(new BasicAWSCredentials(myAccessKey, mySecretKey));
diff -r 22258869aca3 mobile/config/deploy.rb
--- a/mobile/config/deploy.rb   Mon May 17 16:00:39 2010 -0700
+++ b/mobile/config/deploy.rb   Thu May 27 21:18:21 2010 +0000
@@ -9,8 +9,8 @@
 require 'AWS'
 require 'net/ssh'

-ACCESS_KEY_ID = 'CHANGEME'
-SECRET_ACCESS_KEY = 'CHANGEME'
+ACCESS_KEY_ID = 'PUBLICKEY'
+SECRET_ACCESS_KEY = 'SECRETKEY'

 elb = AWS::ELB::Base.new(:access_key_id => ACCESS_KEY_ID, :secret_access_key => SECRET_ACCESS_KEY)
 ec2 = AWS::EC2::Base.new(:access_key_id => ACCESS_KEY_ID, :secret_access_key => SECRET_ACCESS_KEY)
diff -r 22258869aca3 mobile/src/util/AdWhirlUtil.java
--- a/mobile/src/util/AdWhirlUtil.java  Mon May 17 16:00:39 2010 -0700
+++ b/mobile/src/util/AdWhirlUtil.java  Thu May 27 21:18:21 2010 +0000
@@ -40,8 +40,8 @@
        public static final String DOMAIN_USERS_FORGOT = "users_forgot";
        public static final String DOMAIN_USERS_UNVERIFIED = "users_unverified";

-    public static final String myAccessKey = "CHANGEME";
-    public static final String mySecretKey = "CHANGEME";
+    public static final String myAccessKey = "PUBLICKEY";
+    public static final String mySecretKey = "SECRETKEY";

        //Special characters need to be escaped.
        public static final String KEY_SPLIT = "\\|;\\|";
diff -r 22258869aca3 website/inc/class/HouseAd.php
--- a/website/inc/class/HouseAd.php     Mon May 17 16:00:39 2010 -0700
+++ b/website/inc/class/HouseAd.php     Thu May 27 21:18:21 2010 +0000
@@ -101,10 +101,10 @@
     return $this->apps;
   }

-  public static $HOUSEAD_BUCKET = 'CHAMGEME:adrollo-custom-images';
+  public static $HOUSEAD_BUCKET = 'S3BUCKET';
   public static $HOUSEAD_BUCKET_PREFIX = 'http://s3.amazonaws.com/';
-  public static $HOUSEAD_AWS_KEY = 'CHANGEME';
-  public static $HOUSEAD_AWS_SECRET = 'CHANGEME';
+  public static $HOUSEAD_AWS_KEY = 'PUBLICKEY';
+  public static $HOUSEAD_AWS_SECRET = 'SECRETKEY';

   const HOUSEAD_TYPE_BANNER = 1;
   const HOUSEAD_TYPE_ICON = 2;
diff -r 22258869aca3 website/inc/class/SDB.php
--- a/website/inc/class/SDB.php Mon May 17 16:00:39 2010 -0700
+++ b/website/inc/class/SDB.php Thu May 27 21:18:21 2010 +0000
@@ -32,8 +32,8 @@

   private static $instance = null;

-  private static $SDB_ACCESS_KEY_ID = 'CHANGEME';
-  private static $SDB_SECRET_ACCESS_KEY = 'CHANGEME';
+  private static $SDB_ACCESS_KEY_ID = 'PUBLICKEY';
+  private static $SDB_SECRET_ACCESS_KEY = 'SECRETKEY';

   public static function uuid() {
     return sprintf( '%04x%04x%04x%04x%04x%04x%04x%04x',

