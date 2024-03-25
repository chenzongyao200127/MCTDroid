~~~shell
# extract the features
python main.py -R drebin-feature \
    --train_model \
    -D \
    --detection drebin \
    --classifier svm

python main.py -R mamadroid-feature \
    --train_model \
    -D \
    --detection mamadroid \
    --classifier rf
~~~

~~~shell
# Malware Perturbation Set Generating Stage
python main.py -R drebin-feature \
    --create_mps \
    -D \
    --detection drebin \
    --classifier svm

python main.py -R mamadroid-feature \
    --create_mps \
    -D \
    --detection mamadroid \
    --classifier rf    
~~~

~~~shell
# Monte-Carlo Tree Search Attack
python main.py -R drebin-SVM-MCTS \
  -D \
  -N 100 \
  -P 100 \
  --detection drebin \
  --classifier svm \
  --attacker MCTDroid \
  --MCTS_attack

python main.py -R drebin-3nn-MCTS \
  -D \
  -N 100 \
  -P 10 \
  --detection mamadroid \
  --classifier 3nn \
  --attacker MTCDroid \
  --MCTS_attack 

python main.py -R drebin-SVM-ADZ \
  -D \
  -N 100 \
  -P 50 \
  --detection drebin \
  --classifier svm \
  --attacker ADZ \
  --ADZ_attack  

python main.py -R drebin-3nn-ADZ \
  -D \
  -N 100 \
  -P 50 \
  --detection mamadroid \
  --classifier 3nn \
  --attacker ADZ \
  --ADZ_attack 
~~~

# MCTS Example 
~~~shell
[ apigraph-SVM-MCTS | 2024-03-03 | 12:23:39 | root | ForkPoolWorker-1 | INFO ] reward: 100
[INFO    ] root: reward: 100
[ apigraph-SVM-MCTS | 2024-03-03 | 12:23:39 | root | ForkPoolWorker-1 | INFO ] Backpropagate
[INFO    ] root: Backpropagate
└── Node rootcom attck status:False [Q/N: [0.]/1]
    ├── Node tmpx2yr95ap attck status:False [Q/N: [0.12401737]/9]
    │   ├── Node tmpglmgrnoa attck status:False [Q/N: [-0.296036]/1]
    │   │   ├── Node tmp71utx2e7 attck status:False [Unexplored]
    │   │   ├── Node tmpt5z8q4_z attck status:False [Unexplored]
    │   │   ├── Node tmp1j2ctdhv attck status:False [Unexplored]
    │   │   ├── Node tmpwcxf9ds1 attck status:False [Unexplored]
    │   │   ├── Node tmp6xeap4le attck status:False [Unexplored]
    │   │   └── Node tmpddpdvthy attck status:False [Unexplored]
    │   ├── Node tmpxigst5w8 attck status:False [Q/N: [0.37058136]/2]
    │   │   ├── Node tmpjm4lvmtc attck status:False [Q/N: [0.27637123]/1]
    │   │   │   ├── Node tmprzk3h33p attck status:False [Unexplored]
    │   │   │   ├── Node tmpl52uscgc attck status:False [Unexplored]
    │   │   │   ├── Node tmpt7bswzor attck status:False [Unexplored]
    │   │   │   ├── Node tmppg_sfjl8 attck status:False [Unexplored]
    │   │   │   ├── Node tmpy1ne6oia attck status:False [Unexplored]
    │   │   │   └── Node tmpq78axxsb attck status:False [Unexplored]
    │   │   ├── Node tmp0cpg2hzj attck status:False [Unexplored]
    │   │   ├── Node tmpqx_pddzg attck status:False [Unexplored]
    │   │   ├── Node tmpb0j1vy7d attck status:False [Unexplored]
    │   │   ├── Node tmpx9reo2hn attck status:False [Unexplored]
    │   │   └── Node tmpj7z64m5n attck status:False [Unexplored]
    │   ├── Node tmp0lunqa51 attck status:False [Q/N: [-0.01587713]/1]
    │   │   ├── Node tmphxc4ogdt attck status:False [Unexplored]
    │   │   ├── Node tmp6tit_61b attck status:False [Unexplored]
    │   │   ├── Node tmp1ih9pnze attck status:False [Unexplored]
    │   │   ├── Node tmpmztf4zcn attck status:False [Unexplored]
    │   │   ├── Node tmppd5z8dwy attck status:False [Unexplored]
    │   │   └── Node tmpyplvokdm attck status:False [Unexplored]
    │   ├── Node tmpg_ylq2pe attck status:False [Q/N: [0.00197382]/1]
    │   │   ├── Node tmprnl_rn8y attck status:False [Unexplored]
    │   │   ├── Node tmp5c1gxr_5 attck status:False [Unexplored]
    │   │   ├── Node tmpycnw1e3d attck status:False [Unexplored]
    │   │   ├── Node tmpykywokqy attck status:False [Unexplored]
    │   │   ├── Node tmp7mbiaj3f attck status:False [Unexplored]
    │   │   └── Node tmprdj52lwq attck status:False [Unexplored]
    │   ├── Node tmpnlw44lg_ attck status:False [Q/N: [100.02504564]/2]
    │   │   ├── Node tmpkdlg6kra attck status:True [Q/N: 100/1]
    │   │   │   ├── Node tmpzvnppjsd attck status:False [Unexplored]
    │   │   │   ├── Node tmpwy0xlpwg attck status:False [Unexplored]
    │   │   │   ├── Node tmp9pky4a7h attck status:False [Unexplored]
    │   │   │   ├── Node tmp8qggtrbu attck status:False [Unexplored]
    │   │   │   ├── Node tmpjy0d6d80 attck status:False [Unexplored]
    │   │   │   └── Node tmpja110lwz attck status:False [Unexplored]
    │   │   ├── Node tmpmw87aazm attck status:False [Unexplored]
    │   │   ├── Node tmpa6gg7y_l attck status:False [Unexplored]
    │   │   ├── Node tmp3sw_ke4b attck status:False [Unexplored]
    │   │   ├── Node tmpkyufmg2h attck status:False [Unexplored]
    │   │   └── Node tmpn0i4ql5k attck status:False [Unexplored]
    │   └── Node tmpy6hg7h2e attck status:False [Q/N: -100/1]
    │       ├── Node tmpsmqs3gnp attck status:False [Unexplored]
    │       ├── Node tmplr7_jpn2 attck status:False [Unexplored]
    │       ├── Node tmpst48ke5d attck status:False [Unexplored]
    │       ├── Node tmppqfymks_ attck status:False [Unexplored]
    │       ├── Node tmp45klfy5h attck status:False [Unexplored]
    │       └── Node tmpszcctugy attck status:False [Unexplored]
    ├── Node tmpjr8x_7ik attck status:False [Unexplored]
    ├── Node tmpx05kwqcm attck status:False [Unexplored]
    ├── Node tmpxfrxl3vj attck status:False [Unexplored]
    ├── Node tmp4n0ithlx attck status:False [Unexplored]
    └── Node tmphgc1suc_ attck status:False [Unexplored]
[ apigraph-SVM-MCTS | 2024-03-03 | 12:23:39 | root | ForkPoolWorker-1 | INFO ] attack success!
[INFO    ] root: attack success!
[ apigraph-SVM-MCTS | 2024-03-03 | 12:23:39 | root | ForkPoolWorker-1 | INFO ] Attack Success ----- APK: com.box.liaoxingqiu.playA027F72EF44DCB7D0DC5C8A94A7CEA4DF705DBD4.apk
[INFO    ] root: Attack Success ----- APK: com.box.liaoxingqiu.playA027F72EF44DCB7D0DC5C8A94A7CEA4DF705DBD4.apk
[ apigraph-SVM-MCTS | 2024-03-03 | 12:23:39 | root | ForkPoolWorker-1 | INFO ] Final APK State
[INFO    ] root: Final APK State
[ apigraph-SVM-MCTS | 2024-03-03 | 12:23:39 | root | ForkPoolWorker-1 | INFO ] ====================================================================================================
path: /disk2/chenzy/MCTDroid/tmp/tmpkdlg6kra/process/com.box.liaoxingqiu.playA027F72EF44DCB7D0DC5C8A94A7CEA4DF705DBD4.apk
confidence: [1.87047765]
attempt_idx: 0
modification_crash: False
~~~


# RESULT 数据集：Androzoo
                ADZ         MTCDroid        RA
- Drebin
    * svm
        o 10    `[37]`        `[53]`        `[36]`
        o 50    `[70]`        `[91]`        `[55]`  
        o 100   `[86]`        `[95]`        `[58]`
    * mlp
        o 10    `[43]`        `[64]`        `[33]`  
        o 50    `[81]`        `[90]`        `[49]`
        o 100   `[94]`        `[93]`        `[57]`

- mamadroid
    * rf
        o 10    `[74]`        `[97]`        `[65]`
        o 50    `[92]`        `[99]`        `[77]`
        o 100   `[100]`       `[100]`       `[89]`
    * 3nn
        o 10    `[76]`        `[90]`        `[61]`
        o 50    `[85]`        `[95]`        `[64]`
        o 100   `[86]`        `[95]`        `[73]`

~~~shell
# mamadroid_3nn
(torch) (base) [chenzy@MS-7D36 MCTDroid (main ✗)]$ /home/chenzy/anaconda3/envs/torch/bin/python /disk2/chenzy/MCTDroid/calculate_cost.py
Directory            Average Queries                Average Attack Time (s)                 
ADZ_100_50           5.152941176470589              135.87738067963545                      
MCTDroid_100_50      4.221052631578948              177.17542252791554                   
RA_100_50            7.571428571428571              144.11890910069147 


# mamadroid_rf
(torch) (base) [chenzy@MS-7D36 MCTDroid (main ✗)]$ /home/chenzy/anaconda3/envs/torch/bin/python /disk2/chenzy/MCTDroid/calculate_cost.py
Directory            Average Queries                Average Attack Time (s)                
ADZ_100_50           5.758241758241758              151.73800659703684                      
MCTDroid_100_50      4.51                           1237.3163161587715                     
RA_100_50            7.304347826086956              112.85123366635779

# Drebin-SVM
(torch) (base) [chenzy@MS-7D36 MCTDroid (main ✗)]$ /home/chenzy/anaconda3/envs/torch/bin/python /disk2/chenzy/MCTDroid/calculate_cost.py
Directory            Average Queries                Average Attack Time (s)                
MCTDroid_100_50      12.285714285714286             668.2223889094132                      
RA_100_50            15.068965517241379             279.1610857659373
ADZ_100_50           13.203132347091238
~~~