package RDF::Crypt::Decrypter;

use 5.008;
use base qw[RDF::Crypt::PrivateKeyFunction RDF::Crypt::Encrypter];
use common::sense;

use Carp qw[];
use Digest::SHA1 qw[];
use MIME::Base64 qw[];
use RDF::TrineShortcuts qw[];

our $VERSION = '0.001';

# inherit this from Encrypter, but can't use it.
sub new_from_pubkey
{
	Carp::croak("Can't create a Decrypter from a public key.");
}

# inherit this from Encrypter, but can't use it.
sub new_from_webid
{
	Carp::croak("Can't create a Decrypter from a WebID.");
}

sub decrypt_text
{
	my ($self, $text) = @_;
	$text = MIME::Base64::decode_base64($text);
	
	my $key = $self->{privkey};
	my $block_size = $key->size - 16;
		
	my $iv = substr($text, 0, $block_size);
	my $removal_chars = unpack('n', substr($text, $block_size, 2));
	my $scrambled   = substr($text, $block_size + 2);
	$text = '';
	my $v = $iv;
	
	while (length $scrambled)
	{
		my $block  = substr($scrambled, 0, $key->size);
		$scrambled = substr($scrambled, length $block);
		
		if (length $block < $block_size)
		{
			$v = substr($v, 0, length $block);
		}
		
		my $clear  = $key->decrypt($block);
		my $unxor  = "$clear" ^ "$v";
		$v         = $block;
		
		$text .= substr($unxor, 0, $block_size);
	}

	return substr($text, 0, (length $text) - $removal_chars);
}

sub decrypt_model
{
	my ($self, $text, %opts) = @_;
	return RDF::TrineShortcuts::rdf_parse($self->decrypt_text($text), %opts);
}

sub encrypt_text
{
	my ($self, $text) = @_;
	return MIME::Base64::encode_base64($self->{privkey}->private_encrypt($text));
}

1;

=head1 NAME

RDF::Crypt::Decrypter - decryptes encrypted RDF graphs

=head1 DESCRIPTION

A Decrypter object is created using an RSA private key.

RDF::Crypt::Decrypter is a subclass of RDF::Crypt::Encrypter, and can thus
also be used to encrypt graphs for yourself, using just your private key. See
L<RDF::Crypt::Encrypter> for details of the encryption methods.

=head2 Constructors

=over

=item C<< new_from_file($file) >>

Given a filename containing a DER or PEM encoded RSA private key, constructs
a Decrypter object.

=item C<< new_from_string($str) >>

Given a string containing a DER or PEM encoded RSA private key, constructs
a Decrypter object.

=item C<< new_from_privkey($key) >>

Given a L<Crypt::OpenSSL::RSA> private key object, constructs a Decrypter object.

=back

=head2 Object Methods

=over

=item C<< decrypt_model($text, %opts) >>

Given a string that represents an encrypted RDF graph, decrypts and
parses it. Any options are passed along to L<RDF::TrineShortcuts>'
C<rdf_parse> function.

Returns an L<RDF::Trine::Model>.

=item C<< decrypt_text($str) >>

Bonus method - decrypts a literal string which may or may not have anything
to do with RDF.

=back

=head1 SEE ALSO

L<RDF::Crypt::Encrypter>.

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 AUTHOR

Toby Inkster E<lt>tobyink@cpan.orgE<gt>.

=head1 COPYRIGHT

Copyright 2010 Toby Inkster

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
