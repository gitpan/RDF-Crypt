package RDF::Crypt::PublicKeyFunction;

use 5.008;
use common::sense;

use Crypt::OpenSSL::Bignum qw[];
use Crypt::OpenSSL::RSA qw[];
use File::Slurp qw[];
use RDF::TrineShortcuts qw[];

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
	my $key = Crypt::OpenSSL::RSA->new_public_key($key_string);
	return $class->new_from_pubkey($key);
}

sub new_from_pubkey
{
	my ($class, $key) = @_;
	$key->use_pkcs1_padding;
	# OpenSSL command-line tool defaults to this...
	$key->use_md5_hash;
	
	return bless { pubkeys => [$key] }, $class;
}

sub new_from_webid
{
	my ($class, $webid) = @_;
	
	my $model = RDF::Trine::Model->temporary_model;
	RDF::Trine::Parser->parse_url_into_model($webid, $model);
	
	my $query_string = sprintf("PREFIX cert: <http://www.w3.org/ns/auth/cert#>\n"
	                          ."PREFIX rsa: <http://www.w3.org/ns/auth/rsa#>\n"
	                          ."SELECT ?modulus ?exponent ?decExponent ?hexModulus\n"
	                          ."WHERE\n"
	                          ."{\n"
	                          ."    ?key\n"
	                          ."        cert:identity <%s> ;\n"
	                          ."        rsa:modulus ?modulus ;\n"
	                          ."        rsa:public_exponent ?exponent .\n"
	                          ."    OPTIONAL { ?modulus cert:hex ?hexModulus . }\n"
	                          ."    OPTIONAL { ?exponent cert:decimal ?decExponent . }\n"
	                          ."}\n",
	                          $webid);
	my $results = RDF::Query->new($query_string)->execute($model);
	my ($n, $e);
	
	my @keys;
	
	RESULT: while (my $result = $results->next)
	{
		$n = $class->_make_bigint_from_node(
			$result->{'modulus'},  fallback => $result->{'hexModulus'},  fallback_type=>'hex');
			
		$e = $class->_make_bigint_from_node(
			$result->{'exponent'}, fallback => $result->{'decExponent'}, fallback_type=>'dec');
		
		if (defined $n && !$n->is_zero
		&&  defined $e && !$e->is_zero)
		{
			push @keys, Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e);
			$keys[-1]->use_md5_hash;
			$keys[-1]->use_pkcs1_padding;
		}
	}
	
	Carp::carp("No suitable public keys found for WebID <$webid>.")
		unless @keys;
	
	# Smallest first - speeds up verify_text later on...
	return bless {
		pubkeys     => [ sort {$a->size <=> $b->size} @keys ],
		webid_model => $model,
		webid       => $webid,
		}, $class;
}

# modified from CGI::Auth::FOAF_SSL
sub _make_bigint_from_node
{
	my $self = shift;
	my $node = shift;
	my %opts = @_;
	
	if ($node->is_literal)
	{
		if ($node->literal_datatype eq 'http://www.w3.org/ns/auth/cert#hex')
		{
			my $hex = $node->literal_value;
			$hex =~ s/[^0-9A-F]//ig;
			return Crypt::OpenSSL::Bignum->new_from_hex($hex);
		}
		elsif ($node->literal_datatype eq 'http://www.w3.org/ns/auth/cert#decimal'
		or     $node->literal_datatype eq 'http://www.w3.org/ns/auth/cert#int'
		or     $node->literal_datatype =~ m'^http://www.w3.org/2001/XMLSchema#(unsigned(Long|Int|Short|Byte)|positiveInteger|nonNegitiveInteger)$')
		{
			my $dec = $node->literal_value;
			$dec =~ s/[^0-9]//ig;
			return Crypt::OpenSSL::Bignum->new_from_decimal("$dec");
		}
		elsif ($node->literal_datatype =~ m'^http://www.w3.org/2001/XMLSchema#(integer|negitiveInteger|nonPositiveInteger|long|short|int|byte)$')
		{
			my $dec = $node->literal_value;
			$dec =~ s/[^0-9-]//ig;
			return Crypt::OpenSSL::Bignum->new_from_decimal("$dec");
		}
		elsif ($node->literal_datatype eq 'http://www.w3.org/2001/XMLSchema#decimal')
		{
			my ($dec, $frac) = split /\./, $node->literal_value, 2;
			$dec =~ s/[^0-9-]//ig;
			return Crypt::OpenSSL::Bignum->new_from_decimal("$dec");
			
			warn "Ignoring fractional part of xsd:decimal number." if defined $frac;
		}
		elsif (! $node->literal_datatype)
		{
			$opts{'fallback'} = $node;
		}
	}
	
	if (defined $opts{'fallback'} && $opts{'fallback'}->is_literal)
	{
		my $node = $opts{'fallback'};
		
		if ($opts{'fallback_type'} eq 'hex')
		{
			my $hex = $node->literal_value;
			$hex =~ s/[^0-9A-F]//ig;
			return Crypt::OpenSSL::Bignum->new_from_hex("0x$hex");
		}
		else #dec
		{
			my ($dec, $frac) = split /\./, $node->literal_value, 2;
			$dec =~ s/[^0-9]//ig;
			return Crypt::OpenSSL::Bignum->new_from_decimal("$dec");
			
			warn "Ignoring fractional part of xsd:decimal number."
				if defined $frac;
		}
	}
}

1;

