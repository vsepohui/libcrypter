#include <EXTERN.h>               /* From the Perl core */
#include <perl.h>                 /* From the Perl core */
#include "crypter.h"

static PerlInterpreter *my_perl;    /* The Perl interpreter */



struct crypter_result crypter (char *input, unsigned input_length, char *password, unsigned password_length, unsigned obfuscate) {
	int argc = 0;
	char **argv;
	char **env;
    my_perl = perl_alloc();
    perl_construct(my_perl);

    char *embedding[] = { "", "-e", " \
		use 5.022; \
		use warnings;  \
		sub ceil {my $n = shift; return int $n < $n ? int $n + 1 : $n } 	 \
		sub _crypt_string { \
		   my $str  = shift;  my $rnd = shift;  my $obfuscate = shift;\
		   my $n = 0;\
		   my @random = @{$rnd}; my @input = split //, $str;  my $out = ''; \
		    for (my $i = 0 ; $i < scalar @input ; $i ++) {\
				my $chr = $input[$i];  my $ord = ord $chr;\
				my $r = $random[$n];\
				$n = 0 if (++$n >= scalar @random);\
				\
				if ($obfuscate) {\
					my $nr = $r->{generator}->rand($obfuscate);\
					for (1..$nr) {\
						$out .= chr $r->{generator}->rand(256);\
					}\
				}\
				  for my $r (@random) {  \
					my $s = $r->{generator}->rand(256);  \
				  $ord ^= $s;  }    $out .= chr $ord;  \
			}   \
			return $out;\
		}\
		\
		sub _init_random_by_password {  my $password = shift;  my $random = [];    for (1..ceil(length($password)/4)) {  my $p = substr($password, 4*$_-4, 4);  $p .= ' 'x (4 - length $p) if (length $p < 4);     my $x = sprintf(\"%.49f\", unpack('f', $p));  $x = $x ? 1 / $x : 0;   my $rnd = new Strong::Random($x);  $rnd->rand();    $rnd->rand for 1..unpack('s', $p) % 256;    my $seed = sprintf(\"%.8f\", $rnd->{seed});  push @{$random}, {  generator  => new Strong::Random($seed),  seed => $seed,  };  }   return $random;  }  \
		sub crypt { my ($input, $password, $obfuscate) = @_; my $random  = _init_random_by_password($password); my $r = _crypt_string($input, $random, $obfuscate);  return $r;}   \
\
 \
 \
\
		package Strong::Random; \
		use 5.022; use warnings; sub new {  my $class = shift;  my $seed  = shift;    my $self = bless {}, $class;    $self->srand($seed ? abs $seed : undef);    return $self; }   \
		sub _shuffle_seed { ... }\
		  sub _harmonic {  my $self = shift;  my $x = $self->{seed};    state $half_freq = 2/7.0;   my $step = int ($x / $half_freq); $x -= $step * $half_freq; return ($step % 2 ? -1 : 1)*sqrt (1 - $x*$x); }  \
		  sub srand {  my $self = shift;  my $seed = shift // $self->_shuffle_seed();    while ($seed >= 100000000) {  $seed /= 2;  }    $self->{seed} = $seed; } \
		sub rand {  my $self = shift;  my $num = shift;    my $r = ($self->_harmonic()+1)/2.0;   $self->{seed} *= $r+1.5;  $self->{seed} /= 2 if ($self->{seed} >= 100000000);   my $s = $r;  $s =~ s/\\.//;  $r *= substr($s, -5, -1) || 0;  $r = substr($r, 0, 22);  $r =~ s/\\.//;  $r = '0.'. $r;   return $num ? int $num * $r : $r; }  1;  \
				\
		\
		" };
    perl_parse(my_perl, NULL, 3, embedding, NULL);
    perl_run(my_perl);


        dSP;

	ENTER;
        SAVETMPS;

        PUSHMARK(SP);
        EXTEND(SP, 2);
        PUSHs(sv_2mortal(newSVpv(input, input_length)));
        PUSHs(sv_2mortal(newSVpv(password, password_length)));
        PUSHs(sv_2mortal(newSViv(obfuscate)));
        PUTBACK;

    /** Вызов Perl-подпрограммы PrintUID **/
    call_pv("crypt", G_SCALAR);
    SPAGAIN;
    
    STRLEN len;
	SV *sv = POPs;
	char *s = SvPVx(sv, len);
	
	struct crypter_result r;
	r.string = malloc(sizeof(char)*len);
	memcpy(r.string, s, sizeof(char)*len);
	r.size = len;
	    
        PUTBACK;
        FREETMPS;
        LEAVE;    

    perl_destruct(my_perl);
    perl_free(my_perl);
    //PERL_SYS_TERM();
    
    return r;
}



