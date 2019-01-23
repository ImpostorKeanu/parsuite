
# Constants are convenient
DEF = DEFAULT = '[+]'
NOT = NOTICE  = '[-]'
WAR = WARNING = '[!]'

def suffix(s,suf=DEF):
    'Suffix a string with user-supplied input'

    return f'{suf} {s}'

def suffix_print(s, suf=DEF):
    'Print a string after suffixing it with user-supplied input'

    print(suffix(s, suf=suf))

sprint = suffix_print
