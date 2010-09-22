package RDF::Crypt;

use 5.008;

use RDF::Crypt::Verifier;
use RDF::Crypt::Signer;
use RDF::Crypt::Encrypter;
use RDF::Crypt::Decrypter;

our $VERSION = '0.001';

1;

=head1 NAME

RDF::Crypt - semantic cryptography

=head1 DESCRIPTION

This module provides a variety of objects and methods for cryptographically
manipulating (encrypting, decrypting, signing and verifying) RDF graphs using
RSA and WebID.

=head1 SEE ALSO

L<RDF::Crypt::Encrypter>,
L<RDF::Crypt::Decrypter>,
L<RDF::Crypt::Signer>,
L<RDF::Crypt::Verifier>.

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 AUTHOR

Toby Inkster E<lt>tobyink@cpan.orgE<gt>.

=head1 COPYRIGHT

Copyright 2010 Toby Inkster

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
