package RDF::Crypt::Verifier;

use 5.008;
use base 'RDF::Crypt::PublicKeyFunction';
use common::sense;
use constant SIG_MARK => 'CANONICAL_SIGNATURE';

use MIME::Base64 qw[];
use RDF::RDFa::Parser qw[];
use RDF::TrineShortcuts qw[];
use Scalar::Util qw[];

our $VERSION = '0.001';

sub verify_manifest
{
	my ($class, $data, %opts) = @_;
	
	$data = RDF::TrineShortcuts::rdf_parse($data, %opts);
	
	my $query_string = sprintf("PREFIX wot: <http://xmlns.com/wot/0.1/>\n"
	                          ."PREFIX wotox: <http://ontologi.es/wotox#>\n"
	                          ."SELECT *\n"
	                          ."WHERE\n"
	                          ."{\n"
	                          ."    ?document wot:assurance ?assurance .\n"
	                          ."    ?assurance wotox:signature ?signature ;\n"
	                          ."        wotox:signer ?signer .\n"
	                          ."    OPTIONAL { ?assurance wotox:scheme ?scheme . }\n"
	                          ."    OPTIONAL { ?assurance wotox:signedAt ?signedAt . }\n"
	                          ."    FILTER (isIRI(?signer) && isIRI(?document))\n"
	                          ."}\n",
	                          );
	my $results = RDF::Query->new($query_string)->execute($data);
	my @rows    = RDF::TrineShortcuts::flatten_iterator($results);
	my (%docs, %webids);
	
	foreach my $row (@rows)
	{
		if (defined $row->{scheme}
		and $row->{scheme} ne 'http://ontologi.es/wotox#RDF-Crypt')
		{
			next;
		}
		
		unless ($docs{ $row->{document} })
		{
			$docs{ $row->{document} } = RDF::TrineShortcuts::rdf_parse($row->{document});
		}
		unless ($webids{ $row->{signer} })
		{
			$webids{ $row->{signer} } = __PACKAGE__->new_from_webid($row->{signer});
		}
		
		$row->{verification}   = $webids{ $row->{signer} }->verify_model($docs{ $row->{document} }, $row->{signature});
#		$row->{document_model} = RDF::TrineShortcuts::rdf_string($docs{ $row->{document} }, 'ntriples');
#		$row->{verifier}       = $webids{ $row->{signer}->uri };
	}
	
	return @rows;
}

sub verify_text
{
	my ($self, $text, $signature) = @_;
	
	foreach my $key (@{ $self->{pubkeys} })
	{
		return 1
			if $key->verify($text, MIME::Base64::decode_base64($signature))
	}
	return 0;
}

sub verify_model
{
	my ($self, $model, $signature) = @_;
	my $ser = RDF::Trine::Serializer::NTriples::Canonical->new(onfail=>'truncate');
	my $canonical = $ser->serialize_model_to_string($model);
	return $self->verify_text($canonical, $signature);
}

sub verify_embedded_turtle
{
	my ($self, $turtle, $base) = @_;
	
	my $sigmark = $self->SIG_MARK;
	if ($turtle =~ /\{$sigmark\{([^\}]+)\}\}/)
	{
		my $sig = $1;
		
		my $parser = RDF::Trine::Parser::Turtle->new;
		my $model  = RDF::Trine::Model->temporary_model;
		$parser->parse_into_model($base, $turtle, $model);
		
		return $self->verify_model($model, $sig);
	}
	
	return undef;
}

sub verify_embedded_rdfxml
{
	my ($self, $rdfxml, $base) = @_;
	
	my $sigmark = $self->SIG_MARK;
	if ($rdfxml =~ /\{$sigmark\{([^\}]+)\}\}/)
	{
		my $sig = $1;
		
		my $parser = RDF::Trine::Parser::RDFXML->new;
		my $model  = RDF::Trine::Model->temporary_model;
		$parser->parse_into_model($base, $rdfxml, $model);
		
		return $self->verify_model($model, $sig);
	}
	
	return undef;
}

sub verify_embedded_rdfa
{
	my ($self, $rdfa, $base, $config) = @_;
	
	my $p;
	if (Scalar::Util::blessed($rdfa) && $rdfa->isa('RDF::RDFa::Parser'))
	{
		$p = $rdfa;
		$rdfa = $p->dom->toString;
	}
	else
	{
		$p = RDF::RDFa::Parser->new($rdfa, $base, $config);
		$rdfa = $rdfa->toString if ref $rdfa;
	}
	
	$p->consume;
	my $model   = $p->graph;
	my $sig     = undef;
	my $sigmark = $self->SIG_MARK;
	
	if ($p->dom->documentElement->hasAttribute($sigmark))
	{
		$sig = $p->dom->documentElement->getAttribute($sigmark);
	}
	elsif ($rdfa =~ /\{$sigmark\{([^\}]+)\}\}/)
	{
		$sig = $1;
	}
	
	return unless defined $sig;
	return $self->verify_model($model, $sig);
}

1;

=head1 NAME

RDF::Crypt::Verifier - verifies signed RDF graphs

=head1 DESCRIPTION

A Verifier object is created using an RSA public key. The object can be used
to verify signatures for multiple RDF graphs.

=head2 Constructors

=over

=item C<< new_from_file($file) >>

Given a filename containing a DER or PEM encoded RSA public key, constructs
a Verifier object.

=item C<< new_from_string($str) >>

Given a string containing a DER or PEM encoded RSA public key, constructs
a Verifier object.

=item C<< new_from_pubkey($key) >>

Given a L<Crypt::OpenSSL::RSA> public key object, constructs a Verifier object.

=item C<< new_from_webid($uri) >>

Given a WebID with one of more FOAF+SSL public keys, constructs a Verifier
object.

=back

=head2 Class Methods

=over

=item C<< verify_manifest($manifest) >>

Given a manifest created by the Signer, attempts to verify each signature
in it. Returns a list of hashrefs such that each hashref has the following
keys:

=over

=item * B<document> - the URI of the thing that was signed

=item * B<signer> - the WebID of the agent that signed it

=item * B<signedAt> - signature datetime

=item * B<signature> - base64 RSA signature

=item * B<verification> - true/false/undef (see C<verify_model>)

=back

=back

=head2 Object Methods

=over

=item C<< verify_model($model, $signature) >>

Returns true if verification was successful; false but defined if
verification failed; undefined if verification was not attempted
for some reason.

=item C<< verify_embedded_turtle($turtle, $baseuri) >>

Counterpart to Signer's C<sign_embed_turtle>.

=item C<< verify_embedded_rdfxml($xml, $baseuri) >>

Counterpart to Signer's C<sign_embed_rdfxml>.

=item C<< verify_embedded_rdfa($html, $baseuri, \%config) >>

Counterpart to Signer's C<sign_embed_rdfa>.

=item C<< verify_text($str, $signature) >>

Bonus method - verifies a literal string which may or may not have anything
to do with RDF.

=back

=head1 SEE ALSO

L<RDF::Crypt::Signer>.

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 AUTHOR

Toby Inkster E<lt>tobyink@cpan.orgE<gt>.

=head1 COPYRIGHT

Copyright 2010 Toby Inkster

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
