from shim_layer import *
import numpy as np

import os.path

path = './example.txt'

check_file = os.path.isfile(path)

#TODO: Create models based on Phold
#nodes = {1: "10.0.1.1", 2: "10.0.2.2", 4: "10.0.4.4", 5: "10.0.5.5"} #6: "10.0.6.6", 7: "10.0.7.7", 8: "10.0.8.8"}

nodes = {}

def define_nodes(size):
    for i in range(1, size+1):
        if i != 3:
            nodes[i] = "10.0."+str(i)+"."+str(i)

def starting():
    i = False
    while i==False:
        for i in nodes:
            i = os.path.isfile("shared_mem/"+str(i)+".txt")
            if i == False:
                break


def main():
    if len(sys.argv)<2:
        print('pass 1 argument: <process_id> <experiment_size>')
        exit(1)

    pid = int(sys.argv[1])
    size = int(sys.argv[2])

    define_nodes(size)

    shim = shim_layer(pid)

    f = open("shared_mem/"+str(pid)+".txt", "w")

    starting()

    for i in range(1,100):
        time.sleep(5)
        for node_id in nodes:
            if node_id != pid:
                random_variable = np.random.uniform(0, 1)
                if(random_variable > 0.2):
                    shim.app_interface_send(nodes[node_id], input='x')
                    print("%d -> %d" %( pid, node_id ))


if __name__ == '__main__':
    main()
