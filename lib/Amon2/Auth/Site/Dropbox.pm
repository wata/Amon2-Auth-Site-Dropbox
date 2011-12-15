use strict;
use warnings;
use utf8;

package Amon2::Auth::Site::Dropbox;
use Mouse;
use WebService::Dropbox;

our $VERSION = '0.01';

sub moniker { 'dropbox' }

has key => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);
has secret => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

sub _box {
    my ($self) = @_;
    my $box = WebService::Dropbox->new({
        key    => $self->key,
        secret => $self->secret,
    });
    return $box;
}

sub auth_uri {
    my ($self, $c, $callback_uri) = @_;

    my $box = $self->_box();
    my $redirect_uri = $box->login($callback_uri);
    $c->session->set( auth_dropbox => [ $box->request_token, $box->request_secret, ] );
    return $redirect_uri;
}

sub callback {
    my ($self, $c, $callback) = @_;

    my $cookie = $c->session->get('auth_dropbox')
        or return $callback->{on_error}->("Session error");

    my $box = $self->_box();
    $box->request_token($cookie->[0]);
    $box->request_secret($cookie->[1]);
    $box->auth;
    return $callback->{on_finished}->($box->access_token, $box->access_secret, $box->account_info);
}

1;
__END__
