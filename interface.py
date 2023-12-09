import ply.lex as lex
import ply.yacc as yacc

var_consistency  = "default"
var_availability = 0
name = ' '

reserved = {
   'consistency':   'CONS',
   'availability':  'AVAIL',
   'strong':       'STRONG',
   'weak' :         'WEAK',
   'create':        'CREATE',
   'update':        'UPDATE',
   'intent':        'INTENT',
   'delete':        'DELETE'
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
   'ID'
] + list(reserved.values())

#add reserved words as tokens
def t_ID(t):
    r'[a-zA-Z_][a-zA-Z_0-9]*'
    t.type = reserved.get(t.value,'ID')    # Check for reserved words
    return t

print(tokens)

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
t_NUMBER  = r'[0-9]+'

t_ignore = ' \t'
#lexer = lex.lex()

def p_intent(t):
    #TODO: intent name and functionality
    'intent : operation INTENT NAME predicates'
    operator = t[1]
    intent_name = t[3].strip()
    predicate = t[4]
    print(f"Operation: {operator}, Intent Name: {intent_name}, Predicate:{predicate}")

def p_predicates(t):
    '''predicates : predicate COMMA predicate
                    | predicate'''
    t[0] = t[1]
    #TODO: if for comma and first rule

def p_predicate(t):
    'predicate : requirement'
    t[0] = t[1]

def p_requirement(t):
    '''requirement : CONS consistency
                     | AVAIL availability'''
    t[0] = {t[1] : t[2] }

def p_consistency(t):
    '''consistency : STRONG
                     | WEAK'''
    global var_consistency
    var_consistency = str(t[1])
    t[0] = t[1]

def p_availability(t):
    'availability : NUMBER'
    t[0] = int(t[1])

    global var_availability
    var_availability = int(t[1])

def p_operation(t):
    '''operation : CREATE
                 | DELETE
                 | UPDATE'''
    t[0] = t[1]

def p_error(t):
    print(f"Syntax error at {t.value[0]}")
    t.lexer.skip(1)
# Build the lexer
lexer = lex.lex()
# Build the parser
parser = yacc.yacc()

s = "create intent @intentname consistency strong"


result = parser.parse(s)
