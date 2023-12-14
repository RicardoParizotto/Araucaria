import ply.lex as lex

reserved = {
   'consistency':   'CONS',
   'availability':  'AVAIL',
   'strong':       'STRONG',
   'weak' :         'WEAK',
   'create':        'CREATE',
   'update':        'UPDATE',
   'read':          'READ',
   'intent':        'INTENT',
   'delete':        'DELETE',
   'functionality': 'FUNCTIONALITY',
   'high':          'HIGH',
   'low':           'LOW',
   'priority':      'PRIORITY'
}

# List of token names.   This is always required
tokens = [
   'LCOLCH',
   'RCOLCH',
   'LPAREN',
   'RPAREN',
   'LBRACKET',
   'RBRACKET',
   'COMMA',
   'NAME',
   'DDOT',
   'NUMBER',
   'ID',
   'VALUE'
] + list(reserved.values())

#add reserved words as tokens
def t_ID(t):
    r'[a-zA-Z_][a-zA-Z_0-9]*'
    t.type = reserved.get(t.value,'ID')    # Check for reserved words
    return t

# Regular expression rules for simple tokens
t_LCOLCH   = r'\['
t_RCOLCH  = r'\]'
t_LPAREN  = r'\('
t_RPAREN  = r'\)'
t_LBRACKET = r'\{'
t_RBRACKET = r'\}'
t_NAME    = r'@[a-z]+'
t_COMMA   = r','
t_DDOT    = r':'
t_NUMBER  = r'&[0-9]+'
t_VALUE   = r'&[a-zA-Z_0-9][a-zA-Z_0-9]*'

t_ignore = ' \t'
lexer = lex.lex()
