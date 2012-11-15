package Net::IPAddress::Filter::IPFilterDat;

use strict;
use warnings;

# ABSTRACT: An IP address filter from ipfilter.dat
# VERSION

use Scalar::Util ();

use Net::IPAddress::Filter;
use base qw( Net::IPAddress::Filter );

=head1 SYNOPSIS

    use Net::IPAddress::Filter::IPFilterDat;

    my $filter = Net::IPAddress::Filter::IPFilterDat->new();

    $filter->load_file('/tmp/ipfilter.dat');
    # Or
    $filter->load_file($FILEHANDLE);
    # Or
    $filter->add_rule("000.000.000.000 - 000.255.255.255 , 000 , invalid ip");

    print "BLOCKED\n" if $filter->in_filter('192.168.1.20');

=cut

use constant {

    # 000.000.000.000 - 000.255.255.255 , 000 , invalid ip
    RULE_REGEX => qr{
        \A \s*
        ([0-9]{1,3} \. [0-9]{1,3} \. [0-9]{1,3} \. [0-9]{1,3}) # Start IP address
        \s* - \s*
        ([0-9]{1,3} \. [0-9]{1,3} \. [0-9]{1,3} \. [0-9]{1,3}) # End IP address
        \s* , \s*
        (\d+)                                                  # Score
        \s* , \s*
        (.*?)                                                  # Label
        \s* \z
    }xms,
};

=method load_file( )

Fetches rows from an ipfilter.dat-formatted file and adds the ranges to the
filter.

Expects:
    $file - Either a filename, or a filehandle.

Returns:
    Number of rules added from the file.

=cut

sub load_file {
    my $self = shift;
    my $file = shift || return;

    my $FH;

    # A filehandle can be a GLOB ref, or a blessed ref to one of the IO::
    # packages.  reftype() handles boths cases.
    if ( ref($file)
        && ( Scalar::Util::reftype($file) eq 'GLOB' || Scalar::Util::reftype( \$file ) eq 'GLOB' ) )
    {
        $FH = $file;
    }
    else {
        open $FH, '<', $file
            or die __PACKAGE__ . "::load_file() unable to open $file for reading: $!";
    }

    my $rules_added = 0;
    while ( my $line = <$FH> ) {
        $rules_added++ if $self->add_rule($line);
    }

    return $rules_added;
}

=method add_rule( )

Given a line from an ipfilter.dat file, add the rule to the filter.

Expects:
    $rule - A string containing an ipfilter.dat rule.

Returns:
    1 if rule was parsable and added to the filter.
    0 otherwise.

=cut

sub add_rule {
    my $self = shift;
    my $rule = shift || return 0;

    if ( my $data = _parse_rule($rule) ) {
        $self->add_range( $data->{start_ip}, $data->{end_ip} );
        return 1;
    }

    return 0;
}

=func _parse_rule( )

Given a line from an ipfilter.dat file, try to parse out the fields.

Expects:
    $rule - A string containing an ipfilter.dat rule.

Returns:
    A hashref of the fields if parsable.
    Otherwise undef.

=cut

sub _parse_rule {
    my $rule = shift;

    # 000.000.000.000 - 000.255.255.255 , 000 , invalid ip
    if ( $rule =~ RULE_REGEX ) {
        return {
            start_ip => $1,
            end_ip   => $2,
            score    => $3,
            label    => $4,
        };
    }
    return;
}

1;
