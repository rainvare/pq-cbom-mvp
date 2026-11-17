// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract Vulnerable {
    address public owner;
    mapping(address => uint) public balances;

    constructor() {
        owner = msg.sender;
    }

    // Autorización insegura con tx.origin
    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    // Reentrancy: llamada con valor antes de actualizar estado
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // Aleatoriedad débil
    function random() public view returns (uint) {
        return uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
    }

    // delegatecall a dirección arbitraria
    function proxy(address target, bytes memory data) public {
        target.delegatecall(data);
    }

    // selfdestruct sin protección robusta
    function kill() public onlyOwner {
        selfdestruct(payable(msg.sender));
    }

    // ecrecover (ECDSA secp256k1)
    function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(h, v, r, s);
    }
}
