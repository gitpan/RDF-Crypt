use strict;
use warnings;

use inc::Module::Install;

my $dist = 'RDF-Crypt';
my $fn   = "lib/$dist.pm"; $fn =~ s#-#/#g;

name                $dist;
perl_version_from   $fn;
version_from        $fn;
abstract_from       $fn;
readme_from         $fn;
author              'Toby Inkster <tobyink@cpan.org>';
license             'perl';

requires            'common::sense'               => 0;
requires            'Crypt::OpenSSL::Bignum'      => 0;
requires            'Crypt::OpenSSL::Random'      => 0;
requires            'Crypt::OpenSSL::RSA'         => 0;
requires            'Digest::SHA1'                => 0;
requires            'File::Slurp'                 => 0;
requires            'Mail::Message'               => 0;
requires            'Mail::Transport::Sendmail'   => 0;
requires            'Mail::Transport::Send'       => 0;
requires            'Mail::Transport::SMTP'       => 0;
requires            'MIME::Base64'                => 0;
requires            'RDF::RDFa::Parser'           => 0;
requires            'RDF::TrineShortcuts'         => 0;
requires            'Scalar::Util'                => 0;
requires            'Sys::Hostname'               => 0;
test_requires       'Test::More'                  => '0.61';

keywords 'RDF', 'Cryptography', 'RSA', 'WebID', 'Semantic Web', 'Graph';

resources(
	'homepage'   => "http://search.cpan.org/dist/$dist/",
	'repository' => "http://goddamn.co.uk/viewvc/perlmods/$dist/",
	'bugtracker' => "http://rt.cpan.org/Dist/Display.html?Queue=$dist",
	);
	
write_doap_changes;
write_doap_changes_xml;

include 'Test::Signature';
auto_install;
WriteAll(
	'meta' => 1,
	'sign' => 1,
	);
