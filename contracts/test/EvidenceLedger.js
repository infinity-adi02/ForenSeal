const { expect } = require('chai')
const { ethers } = require('hardhat')

describe('EvidenceLedger', function () {
  async function fixture() {
    const [admin, operator, recipient, stranger] = await ethers.getSigners()
    const ledger = await (await ethers.getContractFactory('EvidenceLedger')).deploy()
    await ledger.waitForDeployment()
    return { ledger, admin, operator, recipient, stranger }
  }
  it('anchors a unique batch and rejects duplicate or unauthorized roots', async function () {
    const { ledger, operator, stranger } = await fixture()
    const params = [ethers.id('case-1'), ethers.id('batch-1'), ethers.id('root'), ethers.id('manifest'), 2]
    await expect(ledger.connect(stranger).anchorBatch(...params)).to.be.revertedWith('operator not authorized')
    await ledger.setAuthorized(operator.address, true)
    await ledger.connect(operator).anchorBatch(...params)
    expect((await ledger.getBatch(params[1])).merkleRoot).to.equal(params[2])
    await expect(ledger.connect(operator).anchorBatch(...params)).to.be.revertedWith('batch already anchored')
  })
  it('requires intended recipient acknowledgment for transfer resolution', async function () {
    const { ledger, operator, recipient, stranger } = await fixture()
    await ledger.setAuthorized(operator.address, true)
    const evidence = ethers.id('evidence')
    const tx = await ledger.connect(operator).recordCustody(evidence, 3, recipient.address, ethers.id('reason'))
    const receipt = await tx.wait()
    const transfer = receipt.logs.map(log => { try { return ledger.interface.parseLog(log) } catch { return null } }).find(log => log?.name === 'CustodyEventRecorded').args.transferId
    await expect(ledger.connect(stranger).resolveTransfer(evidence, transfer, true, ethers.id('ack'))).to.be.revertedWith('only intended recipient can acknowledge')
    await ledger.connect(recipient).resolveTransfer(evidence, transfer, true, ethers.id('ack'))
    expect((await ledger.custodyAt(evidence, 1)).eventType).to.equal(4n)
  })
})
