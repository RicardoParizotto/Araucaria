import ply.yacc as yacc

from arauc_lex import *

def p_intent(t):
    #TODO: intent name and functionality
    'intent : operation INTENT NAME LBRACKET predicates RBRACKET'
    operator = t[1]
    intent_name = t[3].strip()
    predicate = t[5]
    print(f"Operation: {operator}, Intent Name: {intent_name}, Predicate:{predicate}")
    t[0] = {"Operation": {operator}, "Name" : intent_name, "Predicate": predicate}


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
                 | UPDATE
                 | READ '''
    t[0] = t[1]

def p_error(t):
    print(f"Syntax error at {t.value}")
    t.lexer.skip(1)
# Build the lexer
#lexer = lex.lex()
# Build the parser
parser = yacc.yacc()
