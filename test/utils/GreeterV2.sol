// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GreeterV2 {
    string public greeting;

    function initialize(string memory _greeting) public {
        greeting = _greeting;
    }

    function resetGreeting() public {
        greeting = "reset";
    }
}
