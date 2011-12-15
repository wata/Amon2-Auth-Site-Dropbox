use inc::Module::Install;
name 'Amon2-Auth-Site-Dropbox';
all_from 'lib/Amon2/Auth/Site/Dropbox.pm';

requires   'Amon2::Auth'         => '0.02';
requires   'Mouse'               => '0.97';
requires   'WebService::Dropbox' => '1.02';

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
