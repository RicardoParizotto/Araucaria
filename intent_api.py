import time

import matplotlib.pyplot as plt
import numpy as np

from arauc_parser import *



intent_list = {}
local_database = {"functionality":"simulation", "inputs":"int"}


gpt = "create intent @machine { functionality : @model [], availability: high, priority high }"

s = "create intent @intentname { functionality : @teste [ @size : &3 ], consistency: strong, priority high }"

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

plt.errorbar(range(0,1000, 100), average, yerr=std, linestyle = 'dotted')

plt.xticks(fontsize = 16)
plt.yticks(fontsize = 16)
plt.grid(zorder=-1, linestyle='--')

plt.ylabel('Compilation time(s)', fontsize=17)
plt.xlabel('# of intents', fontsize=17)

#ax.set_xscale('log')

plt.subplots_adjust(left=0.185, bottom=0.217, right=0.935, top=0.88, wspace=0.2, hspace=0.2)

plt.savefig("analysis_scheduling.pdf")

plt.show()
