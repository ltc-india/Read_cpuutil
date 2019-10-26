selfstat = "/proc/self/stat"
def get_cpu_id():
    fd = open(selfstat)
    print fd.read()
    fd.close()


get_cpu_id()

a = 0

fd = open(selfstat)
while True:
    print fd.read().split(" ")[38]
    for i in range(1000000):
        a = a+1
    fd.seek(0,0)
    a = a+1
