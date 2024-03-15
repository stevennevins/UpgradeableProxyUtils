// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

import {LibUpgradeableProxy} from "../src/LibUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import {Greeter, GreeterV2, WithConstructor, GreeterV2Proxiable} from "./utils/ProxyTestContracts.sol";

contract LibUpgradeableProxyTest is Test {
    ProxyAdmin internal admin;

    function setUp() public {
        admin = new ProxyAdmin();
    }
    function testUUPS() public {
        address proxy = LibUpgradeableProxy.deployUUPSProxy(
            "GreeterProxiable.sol",
            abi.encodeCall(Greeter.initialize, ("hello"))
        );
        Greeter instance = Greeter(proxy);
        address implAddressV1 = LibUpgradeableProxy.getImplementationAddress(proxy);

        assertEq(instance.greeting(), "hello");

        LibUpgradeableProxy.upgradeProxy(
            proxy,
            "GreeterV2Proxiable.sol",
            abi.encodeCall(GreeterV2Proxiable.resetGreeting, ())
        );
        address implAddressV2 = LibUpgradeableProxy.getImplementationAddress(proxy);

        assertEq(instance.greeting(), "reset");
        assertFalse(implAddressV2 == implAddressV1);
    }

    function testTransparent() public {
        address proxy = LibUpgradeableProxy.deployTransparentProxy(
            "Greeter.sol",
            address(admin),
            abi.encodeCall(Greeter.initialize, ("hello"))
        );
        Greeter instance = Greeter(proxy);
        address implAddressV1 = LibUpgradeableProxy.getImplementationAddress(proxy);
        address adminAddress = LibUpgradeableProxy.getAdminAddress(proxy);

        assertFalse(adminAddress == address(0));
        assertEq(instance.greeting(), "hello");

        LibUpgradeableProxy.upgradeProxy(proxy, "GreeterV2.sol", abi.encodeCall(GreeterV2.resetGreeting, ()));

        address implAddressV2 = LibUpgradeableProxy.getImplementationAddress(proxy);

        assertEq(LibUpgradeableProxy.getAdminAddress(proxy), adminAddress);
        assertEq(instance.greeting(), "reset");
        assertFalse(implAddressV2 == implAddressV1);
    }

    function testBeacon() public {
        address beacon = LibUpgradeableProxy.deployBeacon("Greeter.sol", address(admin), abi.encode());
        address implAddressV1 = IBeacon(beacon).implementation();

        address proxy = LibUpgradeableProxy.deployBeaconProxy(beacon, abi.encodeCall(Greeter.initialize, ("hello")));
        Greeter instance = Greeter(proxy);

        assertEq(LibUpgradeableProxy.getBeaconAddress(proxy), beacon);
        assertEq(instance.greeting(), "hello");

        LibUpgradeableProxy.upgradeBeacon(beacon, "GreeterV2.sol");
        address implAddressV2 = IBeacon(beacon).implementation();

        GreeterV2(address(instance)).resetGreeting();

        assertEq(instance.greeting(), "reset");
        assertFalse(implAddressV2 == implAddressV1);
    }

    function testUpgradeBeaconWithoutCaller() public {
        address beacon = LibUpgradeableProxy.deployBeacon("Greeter.sol", address(admin), abi.encode());
        LibUpgradeableProxy.upgradeBeacon(beacon, "GreeterV2.sol", abi.encode());
    }

    function testWithConstructor() public {
        bytes memory constructorData = abi.encode(123);
        address proxy = LibUpgradeableProxy.deployTransparentProxy(
            "WithConstructor.sol",
            msg.sender,
            abi.encodeCall(WithConstructor.initialize, (456)),
            constructorData
        );

        assertEq(WithConstructor(proxy).a(), 123);
        assertEq(WithConstructor(proxy).b(), 456);
    }

    function testNoInitializer() public {
        /// Can access getCode by File:Contract
        bytes memory constructorData = abi.encode(123);
        address proxy = LibUpgradeableProxy.deployTransparentProxy(
            "NoInitializer.sol",
            msg.sender,
            "",
            constructorData
        );

        assertEq(WithConstructor(proxy).a(), 123);
    }

    function testTransparentDeterministic() public {
        bytes32 salt = keccak256("test");
        address proxy = LibUpgradeableProxy.deployTransparentProxy(
            salt,
            "Greeter.sol",
            address(admin),
            abi.encodeCall(Greeter.initialize, ("hello")),
            ""
        );

        Greeter instance = Greeter(proxy);
        address implAddressV1 = LibUpgradeableProxy.getImplementationAddress(proxy);
        address adminAddress = LibUpgradeableProxy.getAdminAddress(proxy);

        assertFalse(adminAddress == address(0));
        assertEq(instance.greeting(), "hello");

        LibUpgradeableProxy.upgradeProxy(proxy, "GreeterV2.sol", abi.encodeCall(GreeterV2.resetGreeting, ()));

        address implAddressV2 = LibUpgradeableProxy.getImplementationAddress(proxy);

        assertEq(LibUpgradeableProxy.getAdminAddress(proxy), adminAddress);
        assertEq(instance.greeting(), "reset");
        assertFalse(implAddressV2 == implAddressV1);
    }
}
