def cricket(cricket_res):
    cricket_res.append({
        'Player' : 'Virat',
        'type':'batsman',
        'team':'india'
    })
    cricket_res.append({
        'Player' : 'snith',
        'type':'batsman',
        'team':'aus'
    })
    return cricket_res


def football(football_res):
    football_res.append({
        'Player' : 'messi',
        'type':'cf',
        'team':'arg'
    })
    football_res.append({
        'Player' : 'ronaldo',
        'type':'striker',
        'team':'port'
    })
    return football_res


def block(res):
    for player in res['cric']:
        print(player['Player'])


def main():
    cricket_list=[]
    football_list=[]
    cric_res=[]
    foot_res=[]
    res=[]

    cric_res=cricket(cricket_list)
    foot_res=football(football_list)

    res = {
        'cric': cricket_list,
        'foot': football_list
    }

    
    block(res)


if __name__== "__main__":
    main()