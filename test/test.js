var should = require('chai').should(),
  assert = require('assert'),
  expect = require('chai').expect;
  nmap = require('../index');

describe('NmapLocation', function () {
  it('returns set NMAP location', function () {
    nmap.NmapLocation.should.equal('nmap.exe');
  });
});
describe('runNMAP', function () {
  it('runs NMAP', function (done) {
    this.timeout(10000);
    nmap.runNMAP("127.0.0.1", function(data){
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[0]).to.include.keys('hostname', 'ip','mac','openPorts','osNmap');
      done();
      
    });
  });
  it('accepts space separated command', function (done) {
    this.timeout(10000);
    nmap.runNMAP("-sn 127.0.0.1", function(data){
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[0]).to.include.keys('hostname', 'ip','mac','openPorts','osNmap');
      done();
    });
  });
  it('accepts multiple hosts', function (done) {
    this.timeout(10000);
    nmap.runNMAP("-sn 127.0.0.1 google.com", function(data){
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[1]).to.include.keys('hostname', 'ip','mac','openPorts','osNmap');
      done();
    });
  });

});
describe('scanForHosts', function () {
  it('scans range of hosts', function (done) {
    this.timeout(10000);
    nmap.runNMAP("-sn 127.0.0.1 google.com", function(data){
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[1]).to.include.keys('hostname', 'ip','mac','openPorts','osNmap');
      done();
      
    });
  });

});