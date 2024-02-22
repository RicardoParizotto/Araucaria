import time
import sys

import matplotlib.pyplot as plt
import numpy as np

from arauc_parser import *
from run import *

plt.rcParams["font.family"] = "Arial"

#this is the database content

functionality_base = {"@teste": {"backend": "python3 run.py", "input": "@size", "input_type": "int"}}
intent = {}

intent_list = {}
#local_database = {"functionality":"simulation", "inputs":"int"}


gpt = "create intent @machine { functionality : @model [], availability: high, priority high }"

s = "create intent @intentname { functionality : @teste [ @size : &3 ], consistency: strong, priority high }"


def conflict_detection():
    print("no_conflict")

def semantic_analysis(intermediary_representation):
    if intermediary_representation["Operation"] == 'read':
        return "intent"
    if intermediary_representation["Operation"] == 'create':
        if(intermediary_representation["Name"] in intent_list.keys()):
             return "intent name already exists"
        if (intermediary_representation["Predicate"]["functionality"]["name"] not in functionality_base.keys()):
             return "functionality does not exist"

    conflict_detection()

    return "passed"

def commit_intent(valid_intermediary_representation):
    if valid_intermediary_representation["Operation"] == 'create':
        db_input = {valid_intermediary_representation["Operation"]}
        intent_list[valid_intermediary_representation["Name"]] = valid_intermediary_representation["Predicate"]
        print(f"Inserting intent " + valid_intermediary_representation["Name"])

        backend_command = functionality_base[valid_intermediary_representation["Predicate"]["functionality"]["name"]]["backend"]

        functionality_input_name = functionality_base[valid_intermediary_representation["Predicate"]["functionality"]["name"]]["input"]

        #print(backend_command + intermediary_representation["Predicate"]["functionality"][])
        print(backend_command + " " + valid_intermediary_representation["Predicate"]["functionality"]["input"][functionality_input_name].split("&")[1])

        parameter = int(valid_intermediary_representation["Predicate"]["functionality"]["input"][functionality_input_name].split("&")[1])

        run_experiment(parameter)


def first_analysis():

    yaxis = []

    for k in range(1, 6):
        index = 0
        for j in range(0, 1000, 100):

            t = time.process_time()

            for i in range(1,j):
                result = parser.parse(s)

            elapsed_time = time.process_time() - t
            try:
                yaxis[index].append(elapsed_time)
            except:
                yaxis.append([elapsed_time])

            index = index + 1

    std = []
    average = []
    index = 0
    for j in yaxis:
        average.append(np.mean(yaxis[index]))
        std.append(np.std(yaxis[index]))
        index = index + 1

    fig,ax = plt.subplots(figsize=(6, 3))

    plt.errorbar(range(0,1000, 100), average, yerr=std, linestyle = 'dashed', color='gray',capsize=5, linewidth=2)

    plt.xticks(fontsize = 16)
    plt.yticks(fontsize = 16)
    plt.grid(zorder=-1, linestyle='--')

    plt.ylabel('Translation time(s)', fontsize=17)
    plt.xlabel('# of intents', fontsize=17)

    #ax.set_xscale('log')

    plt.subplots_adjust(left=0.185, bottom=0.217, right=0.935, top=0.88, wspace=0.2, hspace=0.2)

    plt.savefig("analysis_scheduling.pdf")

    plt.show()

first_analysis()

#if __name__ == "__main__":
#    t = time.process_time()   #benchmark purposes

#    while(True):
#        try:
#            string = input()
#        except EOFError:
#            break

#        parser_result = parser.parse(string)
#        print(parser_result)
#        semantics_result = semantic_analysis(parser_result)
#        if semantics_result == "passed":
#            commit_intent(parser_result)
#        else:
#            print(semantics_result)
#
#        if(string == 'exit()'):
#            break

    #------benckmark---purposes--------------------
#    elapsed_time = time.process_time() - t

#    file = open("results", "a")
#    input_size = int(sys.argv[1])
#    file.write(str(input_size) + "," + str(elapsed_time) + ";\n")
