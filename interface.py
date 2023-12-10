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

def p_intent(t):
    #TODO: intent name and functionality
    'intent : operation INTENT NAME LBRACKET predicates RBRACKET'
    operator = t[1]
    intent_name = t[3].strip()
    predicate = t[5]
    print(f"Operation: {operator}, Intent Name: {intent_name}, Predicate:{predicate}")

def p_predicates(t):
    '''predicates : functionality COMMA requirement COMMA priority'''
    t[0] = {'functionality': t[1], 'requirements' : t[3] , 'priority' : t[5]}

def p_functionality(t):
    'functionality : FUNCTIONALITY DDOT NAME LCOLCH inputs RCOLCH'
    t[0] = t[3]

def p_inputs(t):
    '''inputs : input COMMA inputs
                | input
                | empty '''

def p_empty(p):
    'empty :'
    pass

def p_input(t):
    'input : NAME DDOT VALUE'

def p_priority(t):
    '''priority : PRIORITY HIGH
                  | PRIORITY LOW '''
    t[0] = t[2]

def p_requirements(t):
    '''requirements : requirement COMMA requirements
                    | requirement'''
    t[0] = t[1]
    #TODO: if for comma and first rule

#def p_predicate(t):
#    'predicate : requirement'
#    t[0] = t[1]

def p_requirement(t):
    '''requirement : CONS DDOT consistency
                     | AVAIL DDOT availability'''

    t[0] = {t[1] : t[2] }

def p_consistency(t):
    '''consistency : STRONG
                     | WEAK'''
    t[0] = t[1]

def p_availability(t):
    '''availability : HIGH
                      | LOW'''

    if (t[1] == 'high'):
        t[0] = 4
    else:
        t[0] = 1

def p_operation(t):
    '''operation : CREATE
                 | DELETE
                 | UPDATE'''
    t[0] = t[1]

def p_error(t):
    print(f"Syntax error at {t.value}")
    t.lexer.skip(1)
# Build the lexer
#lexer = lex.lex()
# Build the parser
parser = yacc.yacc()

gpt = "create intent @machine { functionality : @model [], availability: high, priority high }"

s = "create intent @intentname { functionality : @teste [ @size : &3 ], consistency: strong, priority high }"


result = parser.parse(gpt)
