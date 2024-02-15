### ++ Approach ++
#### Credentials
    * Administrator:vau!XCKjNQBv2$ (Admin)

#### Services
    
    ##### 53 DNS
        -
    
    ##### 139,445 SMB
        -
    
    ##### 3389 RDP
        -
    
    ##### 135,49670,49673,59329 RPC
        -

### ++ System Interaction ++
#### Foothold  
	* With Administrator credentials found in .21 we got an elevated shell
	
#### Post-exploitation 
    * Dumping ntds with cme:

        Administrator:60446f9e333abfda8c548cbe11daedc2
        Guest:31d6cfe0d16ae931b73c59d7e0c089c0
        krbtgt:b896b5f9c769cd04d97008292674c1a5
        relia.com\maildmz:ddbe308ff30d828d484098d1c75c6166
        relia.com\jim:be5cb823ee026304b6ed0cd356e34a3c
        relia.com\michelle:18d4098c8d9ff721745b388ad4a442bf
        relia.com\andrea:ce3f12443651168b3793f5fbcccff9db
        relia.com\mountuser:6a2f774420368de1567dea28ab0d3988
        relia.com\iis_service:bb4136aaa06fe1688b300e2f9243e85b
        relia.com\internaladmin:65a883e27cc4714738dfe4dce95001db
        relia.com\larry:47995d3e82d8e698f9b1a9d78c90aa7e
        relia.com\jenny:5ef6ddc308ac24d5423c0b983eee159c
        relia.com\brad:970ba7d4c92f712d0363706d6144c058
        relia.com\anna:f79bec80e693e632f973d32b3489af18
        relia.com\dan:4b22394fc907bd7a74d1af6cc9aca348
        relia.com\milana:2237ff5905ec2fd9ebbdfa3a14d1b2b6
        DC02$:31fcee21451042fa82a7cba4530fe804
        MAIL$:4339112540c2bdf91a37b45e5c8fdea5
        LOGIN$:31d3858ab44671b92c8f74f2b33580fe
        WK01$:da3abf092b31dc5863e126c1a079ec90
        WK02$:89907a9d0b151e99861ff251b52e5f79
        INTRANET$:1c52d9836129bdff62f786b18bfc00a0
        FILES$:a7214310a163f80ba127fc8d171c5076
        WEBBY$:84dbc81f6bb6e298ccd43c4ca75fd48b