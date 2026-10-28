const fs = require('node:fs')
const path = require('node:path')
const { ethers, artifacts, network } = require('hardhat')

async function main() {
  const [deployer] = await ethers.getSigners()
  const factory = await ethers.getContractFactory('EvidenceLedger')
  const contract = await factory.deploy()
  await contract.waitForDeployment()
  const address = await contract.getAddress()
  const artifact = await artifacts.readArtifact('EvidenceLedger')
  const chainId = Number((await ethers.provider.getNetwork()).chainId)
  const deployment = { address, chainId, network: network.name, deployer: deployer.address, abi: artifact.abi }
  const target = path.join(__dirname, '..', '..', 'backend', 'app', 'contract_deployment.json')
  fs.writeFileSync(target, JSON.stringify(deployment, null, 2))
  console.log(`EvidenceLedger deployed to ${address} on chain ${chainId}; ABI saved to ${target}`)
}

main().catch(error => { console.error(error); process.exitCode = 1 })
