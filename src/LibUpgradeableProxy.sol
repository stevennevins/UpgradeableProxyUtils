// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {ITransparentUpgradeableProxy, TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

library Create3CanonicalFactory {
    error ErrorCreatingProxy();
    error ErrorCreatingContract();
    error TargetAlreadyExists();

    // Used when deploying with create2, https://github.com/Arachnid/deterministic-deployment-proxy.
    address internal constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    /**
    @notice The bytecode for a contract that proxies the creation of another contract
    @dev If this code is deployed using CREATE2 it can be used to decouple `creationCode` from the child contract address

  0x67363d3d37363d34f03d5260086018f3:
      0x00  0x67  0x67XXXXXXXXXXXXXXXX  PUSH8 bytecode  0x363d3d37363d34f0
      0x01  0x3d  0x3d                  RETURNDATASIZE  0 0x363d3d37363d34f0
      0x02  0x52  0x52                  MSTORE
      0x03  0x60  0x6008                PUSH1 08        8
      0x04  0x60  0x6018                PUSH1 18        24 8
      0x05  0xf3  0xf3                  RETURN

  0x363d3d37363d34f0:
      0x00  0x36  0x36                  CALLDATASIZE    cds
      0x01  0x3d  0x3d                  RETURNDATASIZE  0 cds
      0x02  0x3d  0x3d                  RETURNDATASIZE  0 0 cds
      0x03  0x37  0x37                  CALLDATACOPY
      0x04  0x36  0x36                  CALLDATASIZE    cds
      0x05  0x3d  0x3d                  RETURNDATASIZE  0 cds
      0x06  0x34  0x34                  CALLVALUE       val 0 cds
      0x07  0xf0  0xf0                  CREATE          addr
  */

    bytes internal constant PROXY_CHILD_BYTECODE = hex"67_36_3d_3d_37_36_3d_34_f0_3d_52_60_08_60_18_f3";

    //                        KECCAK256_PROXY_CHILD_BYTECODE = keccak256(PROXY_CHILD_BYTECODE);
    bytes32 internal constant KECCAK256_PROXY_CHILD_BYTECODE =
        0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;

    /**
    @notice Returns the size of the code on a given address
    @param _addr Address that may or may not contain code
    @return size of the code on the given `_addr`
  */
    function codeSize(address _addr) internal view returns (uint256 size) {
        assembly {
            size := extcodesize(_addr)
        }
    }

    /**
    @notice Creates a new contract with given `_creationCode` and `_salt`
    @param _salt Salt of the contract creation, resulting address will be derivated from this value only
    @param _creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address
    @return addr of the deployed contract, reverts on error
  */
    function create3(bytes32 _salt, bytes memory _creationCode) internal returns (address addr) {
        return create3(_salt, _creationCode, 0);
    }

    /**
    @notice Creates a new contract with given `_creationCode` and `_salt`
    @param _salt Salt of the contract creation, resulting address will be derivated from this value only
    @param _creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address
    @param _value In WEI of ETH to be forwarded to child contract
    @return addr of the deployed contract, reverts on error
  */
    function create3(bytes32 _salt, bytes memory _creationCode, uint256 _value) internal returns (address addr) {
        // Creation code
        bytes memory creationCode = PROXY_CHILD_BYTECODE;

        // Get target final address
        addr = addressOf(_salt);
        if (codeSize(addr) != 0) revert TargetAlreadyExists();

        // Create CREATE2 proxy
        bytes memory initCode = bytes.concat(creationCode, abi.encode());
        (bool success, bytes memory response) = CREATE2_FACTORY.call(bytes.concat(_salt, initCode));
        address proxy = address(bytes20(response));
        if (proxy == address(0) || !success) revert ErrorCreatingProxy();

        // Call proxy with final init code
        (success, ) = proxy.call{value: _value}(_creationCode);
        if (!success || codeSize(addr) == 0) revert ErrorCreatingContract();
    }

    /**
    @notice Computes the resulting address of a contract deployed using address(this) and the given `_salt`
    @param _salt Salt of the contract creation, resulting address will be derivated from this value only
    @return addr of the deployed contract, reverts on error

    @dev The address creation formula is: keccak256(rlp([keccak256(0xff ++ address(this) ++ _salt ++ keccak256(childBytecode))[12:], 0x01]))
  */
    function addressOf(bytes32 _salt) internal view returns (address) {
        address proxy = address(
            uint160(
                uint256(keccak256(abi.encodePacked(hex"ff", CREATE2_FACTORY, _salt, KECCAK256_PROXY_CHILD_BYTECODE)))
            )
        );

        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d6_94", proxy, hex"01")))));
    }
}

library LibUpgradeableProxy {
    address private constant CHEATCODE_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;

    // This is the keccak-256 hash of "eip1967.proxy.rollback" subtracted by 1
    bytes32 private constant _ROLLBACK_SLOT = 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143;

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)) and is validated in the constructor.
     */
    bytes32 internal constant _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    Vm private constant vm = Vm(CHEATCODE_ADDRESS);

    /**
     * @dev Deploys a UUPS proxy using the given contract as the implementation.
     *
     * @param contractName Name of the contract to use as the implementation, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param initializerData Encoded call data of the initializer function to call during creation of the proxy, or empty if no initialization is required
     * @return Proxy address
     */
    function deployUUPSProxy(
        string memory contractName,
        bytes memory initializerData,
        bytes memory implConstructorArgs
    ) internal returns (address) {
        address impl = deployImplementation(contractName, implConstructorArgs);
        return address(_deploy("ERC1967Proxy.sol:ERC1967Proxy", abi.encode(impl, initializerData)));
    }

    /**
     * @dev Deploys a UUPS proxy using the given contract as the implementation.
     *
     * @param contractName Name of the contract to use as the implementation, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param initializerData Encoded call data of the initializer function to call during creation of the proxy, or empty if no initialization is required
     * @return Proxy address
     */
    function deployUUPSProxy(
        bytes32 salt,
        string memory contractName,
        bytes memory initializerData,
        bytes memory implConstructorArgs
    ) internal returns (address) {
        address impl = deployImplementation(contractName, implConstructorArgs);
        return address(_deploy(salt, "ERC1967Proxy.sol:ERC1967Proxy", abi.encode(impl, initializerData)));
    }
    /**
     * @dev Deploys a UUPS proxy using the given contract as the implementation.
     *
     * @param contractName Name of the contract to use as the implementation, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param initializerData Encoded call data of the initializer function to call during creation of the proxy, or empty if no initialization is required
     * @return Proxy address
     */
    function deployUUPSProxy(string memory contractName, bytes memory initializerData) internal returns (address) {
        return deployUUPSProxy(contractName, initializerData, "");
    }

    /**
     * @dev Deploys a transparent proxy using the given contract as the implementation.
     *
     * @param contractName Name of the contract to use as the implementation, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param initialOwner Address to set as the owner of the ProxyAdmin contract which gets deployed by the proxy
     * @param initializerData Encoded call data of the initializer function to call during creation of the proxy, or empty if no initialization is required
     * @return Proxy address
     */
    function deployTransparentProxy(
        string memory contractName,
        address initialOwner,
        bytes memory initializerData
    ) internal returns (address) {
        return deployTransparentProxy(contractName, initialOwner, initializerData, "");
    }

    /**
     * @dev Deploys a transparent proxy using the given contract as the implementation.
     *
     * @param contractName Name of the contract to use as the implementation, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param initialOwner Address to set as the owner of the ProxyAdmin contract which gets deployed by the proxy
     * @param initializerData Encoded call data of the initializer function to call during creation of the proxy, or empty if no initialization is required
     * @return Proxy address
     */
    function deployTransparentProxy(
        bytes32 salt,
        string memory contractName,
        address initialOwner,
        bytes memory initializerData,
        bytes memory implConstructorArgs
    ) internal returns (address) {
        address impl = deployImplementation(contractName, implConstructorArgs);
        return
            address(
                _deploy(
                    salt,
                    "TransparentUpgradeableProxy.sol:TransparentUpgradeableProxy",
                    abi.encode(impl, initialOwner, initializerData)
                )
            );
    }

    /**
     * @dev Deploys a transparent proxy using the given contract as the implementation.
     *
     * @param contractName Name of the contract to use as the implementation, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param initialOwner Address to set as the owner of the ProxyAdmin contract which gets deployed by the proxy
     * @param initializerData Encoded call data of the initializer function to call during creation of the proxy, or empty if no initialization is required
     * @return Proxy address
     */
    function deployTransparentProxy(
        string memory contractName,
        address initialOwner,
        bytes memory initializerData,
        bytes memory implConstructorArgs
    ) internal returns (address) {
        address impl = deployImplementation(contractName, implConstructorArgs);
        return
            address(
                _deploy(
                    "TransparentUpgradeableProxy.sol:TransparentUpgradeableProxy",
                    abi.encode(impl, initialOwner, initializerData)
                )
            );
    }

    /**
     * @dev Deploys an upgradeable beacon using the given contract as the implementation.
     *
     * @param contractName Name of the contract to use as the implementation, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param initialOwner Address to set as the owner of the UpgradeableBeacon contract which gets deployed
     * @return Beacon address
     */
    function deployBeacon(
        string memory contractName,
        address initialOwner,
        bytes memory implConstructorArgs
    ) internal returns (address) {
        address impl = deployImplementation(contractName, implConstructorArgs);
        address beacon = _deploy("UpgradeableBeacon.sol:UpgradeableBeacon", abi.encode(impl));
        UpgradeableBeacon(beacon).transferOwnership(initialOwner);
        return beacon;
    }

    /**
     * @dev Deploys an upgradeable beacon using the given contract as the implementation.
     *
     * @param contractName Name of the contract to use as the implementation, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param initialOwner Address to set as the owner of the UpgradeableBeacon contract which gets deployed
     * @return Beacon address
     */
    function deployBeacon(
        bytes32 salt,
        string memory contractName,
        address initialOwner,
        bytes memory implConstructorArgs
    ) internal returns (address) {
        address impl = deployImplementation(contractName, implConstructorArgs);
        return _deploy(salt, "UpgradeableBeacon.sol:UpgradeableBeacon", abi.encode(impl, initialOwner));
    }

    /**
     * @dev Deploys a beacon proxy using the given beacon and call data.
     *
     * @param beacon Address of the beacon to use
     * @param data Encoded call data of the initializer function to call during creation of the proxy, or empty if no initialization is required
     * @return Proxy address
     */
    function deployBeaconProxy(address beacon, bytes memory data) internal returns (address) {
        return _deploy("BeaconProxy.sol:BeaconProxy", abi.encode(beacon, data));
    }

    /**
     * @dev Deploys a beacon proxy using the given beacon and call data.
     *
     * @param beacon Address of the beacon to use
     * @param data Encoded call data of the initializer function to call during creation of the proxy, or empty if no initialization is required
     * @return Proxy address
     */
    function deployBeaconProxy(bytes32 salt, address beacon, bytes memory data) internal returns (address) {
        return _deploy(salt, "BeaconProxy.sol:BeaconProxy", abi.encode(beacon, data));
    }

    /**
     * @dev Upgrades a proxy to a new implementation contract.
     * @param proxy Address of the proxy to upgrade
     * @param contractName Name of the new implementation contract to upgrade to, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param data Encoded call data of an arbitrary function to call during the upgrade process, or empty if no function needs to be called during the upgrade
     * @param implConstructorArgs abi encoded constructor arguments for deploying the implementation contract
     */
    function upgradeProxy(
        address proxy,
        string memory contractName,
        bytes memory data,
        bytes memory implConstructorArgs
    ) internal {
        address newImpl = _deploy(contractName, implConstructorArgs);

        bytes32 adminSlot = vm.load(proxy, _ADMIN_SLOT);
        if (adminSlot == bytes32(0)) {
            if (data.length > 0) {
                // No admin contract: upgrade directly using interface
                ITransparentUpgradeableProxy(payable(proxy)).upgradeToAndCall(newImpl, data);
            } else {
                ITransparentUpgradeableProxy(payable(proxy)).upgradeTo(newImpl);
            }
        } else {
            if (data.length > 0) {
                ProxyAdmin admin = ProxyAdmin(address(uint160(uint256(adminSlot))));
                admin.upgradeAndCall(ITransparentUpgradeableProxy(payable(proxy)), newImpl, data);
            } else {
                ProxyAdmin admin = ProxyAdmin(address(uint160(uint256(adminSlot))));
                admin.upgrade(ITransparentUpgradeableProxy(payable(proxy)), newImpl);
            }
        }
    }

    /**
     * @dev Upgrades a proxy to a new implementation contract.
     * @param proxy Address of the proxy to upgrade
     * @param contractName Name of the new implementation contract to upgrade to, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param data Encoded call data of an arbitrary function to call during the upgrade process, or empty if no function needs to be called during the upgrade
     */
    function upgradeProxy(address proxy, string memory contractName, bytes memory data) internal {
        upgradeProxy(proxy, contractName, data, "");
    }

    /**
     * @dev Upgrades a beacon to a new implementation contract.
     * @param beacon Address of the beacon to upgrade
     * @param contractName Name of the new implementation contract to upgrade to, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @param implConstructorArgs abi encoded constructor arguments for deploying the implementation contract
     */
    function upgradeBeacon(address beacon, string memory contractName, bytes memory implConstructorArgs) internal {
        address newImpl = _deploy(contractName, implConstructorArgs);
        UpgradeableBeacon(beacon).upgradeTo(newImpl);
    }

    /*
     * @param beacon Address of the beacon to upgrade
     * @param contractName Name of the new implementation contract to upgrade to, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     */
    function upgradeBeacon(address beacon, string memory contractName) internal {
        upgradeBeacon(beacon, contractName, "");
    }

    /**
     * @dev Validates and deploys an implementation contract, and returns its address.
     *
     * @param contractName Name of the contract to deploy, e.g. "MyContract.sol" or "MyContract.sol:MyContract" or artifact path relative to the project root directory
     * @return Address of the implementation contract
     */
    function deployImplementation(
        string memory contractName,
        bytes memory implConstructorArgs
    ) internal returns (address) {
        return _deploy(contractName, implConstructorArgs);
    }
    /**
     * @dev Gets the admin address of a transparent proxy from its ERC1967 admin storage slot.
     * @param proxy Address of a transparent proxy
     * @return Admin address
     */
    function getAdminAddress(address proxy) internal view returns (address) {
        bytes32 adminSlot = vm.load(proxy, _ADMIN_SLOT);
        return address(uint160(uint256(adminSlot)));
    }

    /**
     * @dev Gets the implementation address of a transparent or UUPS proxy from its ERC1967 implementation storage slot.
     * @param proxy Address of a transparent or UUPS proxy
     * @return Implementation address
     */
    function getImplementationAddress(address proxy) internal view returns (address) {
        bytes32 implSlot = vm.load(proxy, _IMPLEMENTATION_SLOT);
        return address(uint160(uint256(implSlot)));
    }

    /**
     * @dev Gets the beacon address of a beacon proxy from its ERC1967 beacon storage slot.
     * @param proxy Address of a beacon proxy
     * @return Beacon address
     */
    function getBeaconAddress(address proxy) internal view returns (address) {
        bytes32 beaconSlot = vm.load(proxy, _BEACON_SLOT);
        return address(uint160(uint256(beaconSlot)));
    }

    function _deploy(string memory contractName, bytes memory implConstructorArgs) private returns (address) {
        bytes memory creationCode = Vm(CHEATCODE_ADDRESS).getCode(contractName);
        address deployedAddress = _deployFromBytecode(abi.encodePacked(creationCode, implConstructorArgs));
        if (deployedAddress == address(0)) {
            revert(
                string.concat(
                    "Failed to deploy contract ",
                    contractName,
                    ' using constructor data "',
                    string(implConstructorArgs),
                    '"'
                )
            );
        }
        return deployedAddress;
    }

    function _deploy(
        bytes32 salt,
        string memory contractName,
        bytes memory implConstructorArgs
    ) private returns (address) {
        bytes memory creationCode = Vm(CHEATCODE_ADDRESS).getCode(contractName);
        address deployedAddress = Create3CanonicalFactory.create3(
            salt,
            abi.encodePacked(creationCode, implConstructorArgs)
        );
        if (deployedAddress == address(0)) {
            revert(
                string.concat(
                    "Failed to deploy contract ",
                    contractName,
                    ' using constructor data "',
                    string(implConstructorArgs),
                    '"'
                )
            );
        }
        return deployedAddress;
    }

    function _deployFromBytecode(bytes memory bytecode) private returns (address) {
        address addr;
        assembly {
            addr := create(0, add(bytecode, 32), mload(bytecode))
        }
        return addr;
    }

    /**
     * @dev Precompile proxy contracts so that they can be deployed by name via the `_deploy` function.
     *
     * NOTE: This function is never called and has no effect, but must be kept to ensure that the proxy contracts are included in the compilation.
     */
    function _precompileProxyContracts() private pure {
        bytes memory dummy;
        dummy = type(ERC1967Proxy).creationCode;
        dummy = type(TransparentUpgradeableProxy).creationCode;
        dummy = type(ProxyAdmin).creationCode;
        dummy = type(UpgradeableBeacon).creationCode;
        dummy = type(BeaconProxy).creationCode;
    }
}
