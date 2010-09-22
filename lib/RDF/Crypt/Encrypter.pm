package RDF::Crypt::Encrypter;

use 5.008;
use base qw[RDF::Crypt::PublicKeyFunction];
use common::sense;

use Carp qw[];
use Crypt::OpenSSL::Random qw[];
use Digest::SHA1 qw[];
use Mail::Message qw[];
use Mail::Transport::Send qw[];
use Mail::Transport::Sendmail qw[];
use Mail::Transport::SMTP qw[];
use MIME::Base64 qw[];
use RDF::TrineShortcuts qw[];
use Sys::Hostname qw[];

our $SENDER;

our $VERSION = '0.001';

sub encrypt_text
{
	my ($self, $text) = @_;
	
	my $key = $self->{pubkeys}[-1];
	Carp::croak('Public key too small. Must be at least 128 bytes.')
		unless $key->size > 127;
	
	my $block_size = $key->size - 16;
	my $iv         = Crypt::OpenSSL::Random::random_bytes($block_size);
	
	my $scrambled;
	my $v = $iv;
	my $last_length;
	
	while (length $text)
	{
		my $block   = substr($text, 0, $block_size);
		$text       = substr($text, length $block);
		
		if (length $block < $block_size)
		{
			$v = substr($v, 0, length $block);
		}
		
		$last_length = length $block;
		
		my $cypher  = $key->encrypt("$block" ^ "$v");
		$scrambled .= $cypher;
		
		$v          = substr($cypher, 0, $block_size);
	}

	return MIME::Base64::encode_base64($iv . pack('n', ($block_size - $last_length)) . $scrambled);
}

sub encrypt_model
{
	my ($self, $model, %opts) = @_;
	$model = RDF::TrineShortcuts::rdf_parse($model, %opts);
	return $self->encrypt_text(RDF::TrineShortcuts::rdf_string($model));
}

sub send_model_by_email
{
	my ($self, $model, $mailopts, $rdfopts) = @_;
	
	Carp::croak("This object was not constructed from a WebID")
		unless defined $self->{webid} && defined $self->{webid_model};

	my $transport;
	$transport = Mail::Transport::SMTP->new(%{$mailopts->{smtp}})
		if $mailopts->{smtp};
	$transport = Mail::Transport::Sendmail->new(%{$mailopts->{sendmail}})
		if $mailopts->{sendmail};
	$transport ||= Mail::Transport::Send->new;
	
	Carp::croak("No method for sending mail.")
		unless defined $transport;

	my @results = 
		map  { substr($_->{mbox}, 7); }
		grep { $_->{mbox} =~ /^mailto:.+\@.+$/i }
		RDF::TrineShortcuts::flatten_iterator(
			RDF::TrineShortcuts::rdf_query(
				sprintf('SELECT * { <%s> foaf:mbox ?mbox } ORDER BY ASC(?mbox)', $self->{webid}),
				$self->{webid_model},
				)
			);
	
	Carp::croak("No valid e-mail address found for WebID <$self->{webid}>")
		unless @results;
	
	my $crypto       = $self->encrypt_model($model, %$rdfopts);
	my $default_from =
		   $SENDER
		|| $ENV{EMAIL_ADDRESS}
		|| ((getlogin||getpwuid($<)||"anonymous").'@'.Sys::Hostname::hostname);

	my %headers = $mailopts->{headers} ? %{$mailopts->{headers}} : ();

	my $msg = Mail::Message->build(
		To            => $results[0],
		From          => ($mailopts->{from} || $default_from),
		Subject       => ($mailopts->{subject} || 'Encrypted data'),
		'X-Mailer'    => __PACKAGE__.'/'.$VERSION,
		attach        => Mail::Message::Body::Lines->new(
			data          => ["This data has been encrypted for:\n", $self->{webid}."\n"],
			mime_type     => 'text/plain',
			disposition   => 'inline',
			),
		attach        => Mail::Message::Body::Lines->new(
			data          => ["$crypto\n"],
			mime_type     => 'application/prs.rdf+xml+crypt',
			disposition   => 'attachment; filename="'.($mailopts->{filename}||'data.rdf-crypt').'"',
			),
		%headers
		);
		
	return unless $msg->send($transport);
	return $msg->messageId;
}

1;

=head1 NAME

RDF::Crypt::Encrypter - encrypts RDF graphs

=head1 DESCRIPTION

An Encrypter object is created using an RSA public key. The object can be used
to encrypt an RDF graph for a recipient.

=head2 Constructors

=over

=item C<< new_from_file($file) >>

Given a filename containing a DER or PEM encoded RSA public key, constructs
an Encrypter object.

=item C<< new_from_string($str) >>

Given a string containing a DER or PEM encoded RSA public key, constructs
an Encrypter object.

=item C<< new_from_pubkey($key) >>

Given a L<Crypt::OpenSSL::RSA> public key object, constructs an Encrypter object.

=item C<< new_from_webid($uri) >>

Given a WebID with one of more FOAF+SSL public keys, constructs an Encrypter
object. If multiple public keys are associated with the same WebID, then the one
with the largest key size (most secure) is used.

=back

=head2 Object Methods

=over

=item C<< encrypt_model($model) >>

Returns an encrypted serialisation of the data.

The encryption works by serialising the data as RDF/XML, then
encrypting it with C<encrypt_text>.

=item C<< send_model_by_email($model, \%opts) >>

This method only works on objects that were constructed using C<new_from_webid>.
Encrypts the model for the holder of the WebID, and sends it to an address
specified in the WebID profile using foaf:mbox.

Options:

=over

=item * B<sendmail> - hashref of options for L<Mail::Transport::Sendmail>. The
mere presence of this hashref will trigger L<Mail::Transport::Sendmail> to
be used as the delivery method.

=item * B<smtp> - hashref of options for L<Mail::Transport::SMTP>. The
mere presence of this hashref will trigger L<Mail::Transport::SMTP> to
be used as the delivery method.

=item * B<from> - email address for the message to come from.

=item * B<subject> - message subject.

=item * B<filename> - filename for encrypted attachment.

=item * B<headers> - hashref of additional mail headers.

=back

Returns a the message's Message-ID, or undef if unsuccessful.

=item C<< encrypt_text($str) >>

Bonus method - encrypts a literal string which may or may not have anything
to do with RDF.

The return value is a base64-encoded string. The base64-decoded value consists
of: (1) an initialisation vector, sixteen bytes shorter than the size of the
key; (2) a 32-bit big-endian signed integer indicating the length of padding
which was added to the payload of the message during encryption; (3) the payload,
encrypted using cipher-block chaining with OEAP, with block length sixteen bytes
shorter than the key size. These three parts are concatenated together in that
order.

=back

=head1 SEE ALSO

L<RDF::Crypt::Decrypter>.

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 AUTHOR

Toby Inkster E<lt>tobyink@cpan.orgE<gt>.

=head1 COPYRIGHT

Copyright 2010 Toby Inkster

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
