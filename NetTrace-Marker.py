
import re
import sys
import pprint
import csv
from matplotlib.cbook import flatten



def getFinaloutPut(NextDict={}):
    outputlst =  NextDict['ip_port_conn']
    outputlst.append(NextDict['totalpackets:_ab'])
    outputlst.append(NextDict['totalpackets:_ba'])

    outputlst.append(NextDict['ackpktssent:_ab'])
    outputlst.append ( NextDict['ackpktssent:_ba'])

    outputlst.append(NextDict['uniquebytessent:_ab'])
    outputlst.append(NextDict['uniquebytessent:_ba'])

    outputlst.append(NextDict['actualdatapkts:_ab'])
    outputlst.append(NextDict['actualdatapkts:_ba'])

    outputlst.append(NextDict['mssrequested:_ab'])
    outputlst.append(NextDict['mssrequested:_ba'])


    outputlst.append(NextDict['maxsegmsize:_ab'])
    outputlst.append(NextDict['maxsegmsize:_ba'])

    outputlst.append(NextDict['minsegmsize:_ab'])
    outputlst.append(NextDict['minsegmsize:_ba'])

    outputlst.append(NextDict['avgsegmsize:_ab'])
    outputlst.append(NextDict['avgsegmsize:_ba'])

    outputlst.append(NextDict['Binitialwindow:_ab'])
    outputlst.append(NextDict['Binitialwindow:_ba'])

    outputlst.append(NextDict['initialwindow:_ab'])
    outputlst.append(NextDict['initialwindow:_ba'])

    outputlst.append(NextDict['dataxmittime:_ab'])
    outputlst.append(NextDict['dataxmittime:_ba'])

    outputlst.append(NextDict['idletimemax:_ab'])
    outputlst.append(NextDict['idletimemax:_ba'])

    outputlst.append(NextDict['throughput:_ab'])
    outputlst.append(NextDict['throughput:_ba'])

    outputlst.append(NextDict['RTTsamples:_ab'])
    outputlst.append(NextDict['RTTsamples:_ba'])

    outputlst.append(NextDict['RTTmin:_ab'])
    outputlst.append(NextDict['RTTmin:_ba'])

    outputlst.append(NextDict['RTTmax:_ab'])
    outputlst.append(NextDict['RTTmax:_ba'])

    outputlst.append(NextDict['RTTavg:_ab'])
    outputlst.append(NextDict['RTTavg:_ba'])

    outputlst.append(NextDict['RTTstdev:_ab'])
    outputlst.append(NextDict['RTTstdev:_ba'])

    outputlst.append(NextDict['RTTfrom3WHS:_ab'])
    outputlst.append(NextDict['RTTfrom3WHS:_ba'])
    return  outputlst
def lstStrip(s):
    return s.replace(' ', '')

def tfilter(l):
#     print l
    string = l[0]
    if string[0] == '\t':
        string = string[1:]
    return [string]

class TcpInfo():
    """docstring for """

    def __init__(self, ip_port_lst, infodict):
        self.lst = ip_port_lst
        self.dict = infodict

def earaser(s):
    danweibiao = ['pkts', 'bytes', 'times', 'pkt', 'secs', 'ms', 'Bps']
    for idx, dw in enumerate(danweibiao):
        if dw in s:
            if idx == 0:
                s = s[:-4]

            if idx == 1:
                # print '1'
                s = s[:-5]

            if idx == 2:
                # print '2'
                s = s[:-5]

            if idx == 3:
                print '3'
                s = s[:-3]

            if idx == 4:
                s = s[:-4]

            if idx == 5:
                s = s[:-2]
            if idx == 6:
                s = s[:-3]
    return s

def tabfilter(oneline):
    oneline = oneline.split("     ")
    filtered_oneline = [s.replace(' ', '') for s in oneline if s.replace(' ', '') != '']
    return filtered_oneline


def tcpheaddict(Tcp0):
    fullNotNonelist = []
    for ix, eachlist in enumerate(Tcp0.split('\n')):
        haveNonelist = map(tabfilter, eachlist.split('    '))
        # print haveNonelist
        noNonelist = [l for l in haveNonelist if l != []]
        fullNotNonelist += noNonelist
    # print ix,noNonelist
    fullNotNonelist = [pp for pp in fullNotNonelist if pp!= ['**WARNING:presenceofhardwareduplicatesmakesthesefiguressuspect!']]
    Bug_Attr_lst =  [Bug_Attr for Bug_Attr in fullNotNonelist if ':'in Bug_Attr[0] and Bug_Attr[0][-1]!=':' and '0:0' not in Bug_Attr[0]]

    # pprint.pprint(fullNotNonelist)
    # print '--------Space--Bug---------'

    # print '-------------Real Bug-------------'
    Real_bug =  [b for b in Bug_Attr_lst if re.match(r"(\w+):(\d+)",b[0]) ]
    # pprint.pprint(Real_bug)
    for ech in Real_bug:


        fullNotNonelist.insert(fullNotNonelist.index(ech)+1,[ech[0].split(':')[1]])
        fullNotNonelist[fullNotNonelist.index(ech)] = [ech[0].split(':')[0]]

    # view the start of ip , port and attribu
    # for idx,bb in enumerate( fullNotNonelist):
    # 	print idx,bb



    TCPNumber = fullNotNonelist[62][0]
    hosta = fullNotNonelist[64][0]
    hostb = fullNotNonelist[66][0]
    fullconn = fullNotNonelist[67][0]

    ipa = hosta.split(':')[0]
    porta = hosta.split(':')[1]
    ipb = hostb.split(':')[0]
    portb = hostb.split(':')[1]

    ip_port_lst = []

    # print TCPNumber[:-1][13:]
    # print ipa,porta
    # print ipb,portb
    # print fullconn[14:][:-16]

    ip_port_lst.append(TCPNumber[:-1][13:])
    ip_port_lst.append(ipa)
    ip_port_lst.append(porta)
    ip_port_lst.append(ipb)
    ip_port_lst.append(portb)
    ip_port_lst.append(fullconn[14:][:-16])

    # Thins is only different that head and node has   fullnotNonelist begin index

    attribu_doubl_unmark = fullNotNonelist[14:][::2]

    #Rename Initial Window
    attribu_doubl_unmark[attribu_doubl_unmark.index(['initialwindow:'])] = ['Binitialwindow:']
    attribu_doubl_unmark[attribu_doubl_unmark.index(['initialwindow:'])] = ['Binitialwindow:']


    value = fullNotNonelist[14:][1::2]
    # print value
    # get one direction list
    # print '****a-b*******'

    attribu_ba_unmark = attribu_doubl_unmark[1::2]
    # print attribu_ab_unmark
    # print '*****b-a****'

    attribu_ab_unmark = attribu_doubl_unmark[::2]
    # print attribu_ba_unmark



    attribu_ba_marked = map(lambda l: l[0] + '_ba', attribu_ba_unmark)
    attribu_ab_marked = map(lambda l: l[0] + '_ab', attribu_ab_unmark)

    value_marked = map(lambda l: l[0], value)


    # to sigl list
    final_Attri_lst = list(flatten(zip(attribu_ab_marked, attribu_ba_marked)))
    # pprint.pprint( final_Attri_lst )


    # final_Attri_lst = list(flatten(zip(attribu_ab_marked,attribu_ba_marked))
    final_Dict = dict(zip(final_Attri_lst, value_marked))
    final_Dict['ip_port_conn'] = ip_port_lst
    # print final_Dict
    return final_Dict



def tcpdict(Tcp666):
    fullNotNonelist = []
    for ix, eachlist in enumerate(Tcp666.split('\n')):
        haveNonelist = map(tabfilter, eachlist.split('    '))
        # print haveNonelist
        noNonelist = [l for l in haveNonelist if l != []]
        fullNotNonelist += noNonelist
        fullNotNonelist = map(tfilter,fullNotNonelist)

    fullNotNonelist = [pp for pp in fullNotNonelist if pp!= ['**WARNING:presenceofhardwareduplicatesmakesthesefiguressuspect!']]
    # print 'hsx',fullNotNonelist
    #check space Bug 
    # print '------space--Bug----------'
    # pprint.pprint(fullNotNonelist)
    Bug_Attr_lst =  [Bug_Attr for Bug_Attr in fullNotNonelist if ':'in Bug_Attr[0] and Bug_Attr[0][-1]!=':' and '0:0' not in Bug_Attr[0]]

    # pprint.pprint(fullNotNonelist)
    # print '--------Space--Bug---------'

    # print '-------------Real Bug-------------'
    Real_bug =  [b for b in Bug_Attr_lst if re.match(r"(\w+):(\d+)",b[0]) ]
    # pprint.pprint(Real_bug)
    for ech in Real_bug:


        fullNotNonelist.insert(fullNotNonelist.index(ech)+1,[ech[0].split(':')[1]])
        fullNotNonelist[fullNotNonelist.index(ech)] = [ech[0].split(':')[0]+':']
    # print '---------fixed------fullNotNonelist----------'
    # pprint.pprint(fullNotNonelist)


    # view the start of ip , port and attribu
    # for idx,bb in enumerate( fullNotNonelist):
    # 	print idx,bb
    #Rename aready exsist
    # fullNotNonelist[180] = ['Binitialwindow:']
    # fullNotNonelist[182] = ['Binitialwindow:']


    TCPNumber = fullNotNonelist[0][0]
    hosta = fullNotNonelist[2][0]
    hostb = fullNotNonelist[4][0]
    fullconn = fullNotNonelist[5][0]

    ipa = hosta.split(':')[0]
    porta = hosta.split(':')[1]
    ipb = hostb.split(':')[0]
    portb = hostb.split(':')[1]

    ip_port_lst = []

    # print TCPNumber[:-1][13:]
    # print ipa,porta
    # print ipb,portb
    # print 'test---', fullconn[fullconn.index(":") + 1:fullconn.index(":") + 4]

    ip_port_lst.append(TCPNumber[:-1][13:])
    ip_port_lst.append(ipa)
    ip_port_lst.append(porta)
    ip_port_lst.append(ipb)
    ip_port_lst.append(portb)
    ip_port_lst.append(fullconn[fullconn.index(":") + 1:fullconn.index(":") + 4])

    # Thins is only different that head and node has   fullnotNonelist begin index

    attribu_doubl_unmark = fullNotNonelist[fullNotNonelist.index(['filename:'])+4:][::2]
    # print attribu_doubl_unmark
    attribu_doubl_unmark[attribu_doubl_unmark.index(['initialwindow:'])] = ['Binitialwindow:']
    attribu_doubl_unmark[attribu_doubl_unmark.index(['initialwindow:'])] = ['Binitialwindow:']



    value = fullNotNonelist[fullNotNonelist.index(['filename:'])+4:][1::2]
    # print value
    # get one direction list
    # print '****a-b*******'

    attribu_ba_unmark = attribu_doubl_unmark[1::2]
    # print attribu_ab_unmark
    # print '*****b-a****'

    attribu_ab_unmark = attribu_doubl_unmark[::2]
    # print attribu_ba_unmark
    # print 'shoul be change',attribu_ab_unmark[52],attribu_ab_unmark[53]



    attribu_ba_marked = map(lambda l: l[0] + '_ba', attribu_ba_unmark)
    attribu_ab_marked = map(lambda l: l[0] + '_ab', attribu_ab_unmark)

    value_marked = map(lambda l: l[0], value)
    # print attribu_ba_marked
    # print attribu_ab_marked
    # print attribu_ba_marked
    # print attribu_ab_marked

    # to sigl list
    final_Attri_lst = list(flatten(zip(attribu_ab_marked, attribu_ba_marked)))
    # final_Attri_lst = list(flatten(zip(attribu_ab_marked,attribu_ba_marked))
    final_Dict = dict(zip(final_Attri_lst, value_marked))
    # print final_Attri_lst
    # print value_marked

    final_Dict['ip_port_conn'] = ip_port_lst
    # print 'This is final Dict :'
    # pprint.pprint( final_Dict)
    return final_Dict
def main(argv):


    if len(argv) != 2:
        print "Netmate txt to csv/xls:"
        print "    Usage: python <Netmate txt file path >"
        print ""
        # print argv[1]

    with open(argv[1]) as f:
            txt = f.read()
            connections = re.split(r"=========*", txt)

            d0 = tcpheaddict(connections[0])

            writer = csv.writer(file('NetTrace_data_set.csv', 'wb'))
            writer.writerow( map(earaser,getFinaloutPut(d0)) )


            for id in range(1, 456):
                NextDict = tcpdict(connections[id])
                writer.writerow( map(earaser,getFinaloutPut(NextDict)) )
            print('''
                              _,._  
                 __.'   _)  
                <_,)'.-"a\  
                  /' (    \  
      _.-----..,-'   (`"--^  
     //              |  
    (|   `;      ,   |  
      \   ;.----/  ,/  
       ) // /   | |\ \  
       \ \\`\   | |/ /  
        \ \\ \  | |\/  
         `" `"  `"`  


            ''')
            print 'Success! check folder for Netmate date set file'
            sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)