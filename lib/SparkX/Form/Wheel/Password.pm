package SparkX::Form::Wheel::Password;

use Moose;
use Data::Password qw(IsBadPassword);

require SparkX::Form::Field::Password;
extends 'SparkX::Form::Field::Password';

has 'following_chars' => (
    isa      => 'Int',
    is       => 'rw',
    required => 0,
    default  => 0,
);

has 'groups' => (
    isa      => 'Int',
    is       => 'rw',
    required => 0,
    default  => 0,
);

has 'min_length' => (
    isa      => 'Int',
    is       => 'rw',
    required => 0,
    default  => 6,
);

has 'max_length' => (
    isa      => 'Int',
    is       => 'rw',
    required => 0,
    default  => 0,
);

has 'dictionary_length' => (
    isa      => 'Int',
    is       => 'rw',
    required => 0,
    default  => 0,
);

has 'dictionaries' => (
    isa      => 'ArrayRef[Str]',
    is       => 'rw',
    required => 0,
    default  => sub { [] },
);

sub _dictionary_msg {
    my ($self) = shift;
    return '' unless $self->dictionary_length;

    # TODO: Provide a way to link to some online copy of the dictionary?
    return sprintf 'No set of characters in your password that is %s or more characters long may be found in our dictionary',
      $self->dictionary_length;
}

sub _groups_msg {
    my ($self) = shift;
    return '' if ($self->groups or $self->groups == 1);
    return
      sprintf
      ' There must be more than %s runs of a type of character in your password. That is, ABCD is 1, ABCD123 is 2, ABCD123A is 3',
      $self->groups;
}

sub _length_msg {
    my ($self) = shift;
    return '' if ($self->max_length == 0 and $self->min_length == 0);

    if ($self->max_length == 0) {
        return $self->min_length . ' or more characters';
    }
    if ($self->min_length == 0) {
        return sprintf 'At most %s characters', $self->max_length;
    }
    return 'Between %s and %s characters', $self->min_length, $self->max_length;
}

sub _criteria {
    my ($self) = @_;
    my (@messages) = grep { $_ ne '' } ($self->_dictionary_msg, $self->_groups_msg, $self->_length_msg,);
    return 'Any password should work' if not @messages;
    return join "\n", 'The criteria for a password is as follows:', @messages;
}

sub _validate {
    my $self = shift;

    my $res;
    eval {
        $Data::Password::DICTIONARY   = $self->dictionary_length;
        $Data::Password::FOLLOWING    = $self->following_chars;
        $Data::Password::GROUPS       = $self->groups;
        $Data::Password::MINLEN       = $self->min_length;
        $Data::Password::MAXLEN       = $self->max_length;
        @Data::Password::DICTIONARIES = @{$self->dictionaries} if @{$self->dictionaries};
        $res                          = IsBadPassword($self->value);
    };

    # If it returns something, it's a new address in Mail::Address format
    $self->error(sprintf 'Password Failed criteria with \'%s\'. %s', $res, $self->_criteria) if $res;

    !$res;
}

1;
__END__

=head1 DESCRIPTION

SparkX::Form::Field::Password

=cut
