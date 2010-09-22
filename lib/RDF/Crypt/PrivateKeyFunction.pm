package RDF::Crypt::PrivateKeyFunction;

use 5.008;
use common::sense;

use Crypt::OpenSSL::RSA qw[];
use File::Slurp qw[];

our $VERSION = '0.001';

sub new_from_file
{
	my ($class, $key_file) = @_;
	my $key_string = File::Slurp::slurp($key_file);
	return $class->new_from_string($key_string);
}

sub new_from_string
{
	my ($class, $key_string) = @_;
	my $key = Crypt::OpenSSL::RSA->new_private_key($key_string);
	return $class->new_from_privkey($key);
}

sub new_from_privkey
{
	my ($class, $key) = @_;
	$key->use_pkcs1_padding;
	# OpenSSL command-line tool defaults to this...
	$key->use_md5_hash;
	
	return bless { privkey=>$key }, $class;
}

1;

