### [M-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service (DoS) attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle:enterRaffle` function loops through the `players` array to check for duplicates. However, the longer
the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle stats will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make

```javascript
// @audit Dos Attack
@>    for(uint256 i = 0;i<players.length-1;i++){
        for(uint256 j = i+1;j<players.length;j++){
            require(players[i] != players[j],"PuppyRaffle:Duplicate Player");
        }
    }
```

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering, and causing a rush at the start of a raffle to be one of the first entrantss in the queue.

An attacker might make the `PuppyRaffle::entrants` array so big, that no one else entersk, guarenteeing themselves the win

**Proof of Completion:**

If we have 2 sets of 100 players enter, the gas costs will be as such:

- 1st 100 players: ~6252048
- 2nd 100 players: ~18068138

This more than 3x more expensive for the second 100 players

<details>
<summary> PoC</summary>
Place the following

```javascript
    function test_denialOfService() public{

        vm.txGasPrice(1);

        // Let's enter 100 players
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for(uint256 i = 0;i<playersNum;i++){
            players[i] = address(i);
        }
        // see how much gas it costs
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value : entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsedFirst = (gasStart -gasEnd);
        console.log("Gas cost of the first 100 players: ",gasUsedFirst);

        // now for the 2nd 100 players
        address[] memory playersTwo  = new address[](playersNum);
        for(uint256 i = 0;i<playersNum;i++){
            playersTwo[i] = address(i+playersNum); // 0, 1, 2, -> 100, 101, 102
        }
        // see how much gas it costs
        uint256 gasStartSecond = gasleft();
        puppyRaffle.enterRaffle{value : entranceFee * players.length}(playersTwo);
        uint256 gasEndSecond = gasleft();
        uint256 gasUsedSecond = (gasStartSecond - gasEndSecond) * tx.gasprice;
        console.log("Gas cost of the second 100 players: ",gasUsedSecond);

        assert(gasUsedFirst < gasUsedSecond);
    }

```

</details>

**Recommended Mitigation:** There are few recommendations.

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup of whether a user has already entered

```diff
+ mapping(address => uint256) public addressToRaffleId;
+ uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable{
        require(msg.value == entranceFee * newPlayers.length,"PuppyRaffle: Must send enough to enter raffle");
        for(uint256 i = 0;i < newPlayers.length;i++){
            players.push(newPlayers[i]);
+           addressToRaffleId[newPlayers[i]] = raffleId;
        }
    }
-   // Check for duplicates
+   // Check for duplicates only from  the new players
+   for (uint256 i = 0; i < newPlayers.length; i++){
+        require(addressToRaffleId[newPlayers[i]] != raffleId,"PuppyRaffle: Duplicate Player");
+   }
-   for(uint256 i = 0; i < players.length; i++){
-       for(uint256 j = i +1;j<players.length; j++){
-            require(players[i]!=players[j],"PuppyRaffle: Duplicate player");
-         }
-      }
       emit RaffleEnter(newPlayers);
    }
.
.
    function selectWinner() external {
+       raffleId = raffleId +1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over ");
    }

```

Alternatively, you could see [Openzeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/5.x/api/utils#EnumerableSet).
