var should = require('chai').should(),
  assert = require('assert'),
  expect = require('chai').expect;
nmap = require('../index');


describe('runNMAP', function () {

  it('runs NMAP', function (done) {
    
    this.timeout(10000);
    nmap.runNMAP("127.0.0.1", function (data) {
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[0]).to.include.keys('hostname', 'ip', 'mac', 'openPorts', 'osNmap');
      done();
    });

  });

  it('accepts space separated command', function (done) {
    
    this.timeout(10000);
    nmap.runNMAP("-sn 127.0.0.1", function (data) {
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[0]).to.include.keys('hostname', 'ip', 'mac', 'openPorts', 'osNmap');
      done();
    });
  });

  it('accepts multiple hosts', function (done) {
    
    this.timeout(10000);
    nmap.runNMAP("-sn 127.0.0.1 google.com", function (data) {
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[1]).to.include.keys('hostname', 'ip', 'mac', 'openPorts', 'osNmap');
      done();
    });
  });
  it('returns failure data for bad requests', function (done) {
    
    this.timeout(10000);
    nmap.runNMAP("127.0.0.", function (data) {
      
    },function(err){
      expect(err).to.be.a('string');
      done();
    });

  });

});

describe('quickScan', function () {
  
  it('scans range of hosts', function (done) {
    
    this.timeout(10000);
    nmap.quickScan("127.0.0.1 google.com", function (data) {
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[1]).to.include.keys('hostname', 'ip', 'mac', 'openPorts', 'osNmap');
      done();

    });
  });
  it('returns failure data for bad requests', function (done) {
    
    this.timeout(10000);
    nmap.quickScan("127.0.0.", function (data) {
      
    },function(err){
      expect(err).to.be.a('string');
      done();
    });

  });

});

describe('osAndPortScan', function () {
  
  it('scans hosts for open ports and OS data', function (done) {
    
    this.timeout(20000);
    nmap.osAndPortScan("google.com", function (data) {
      NMAPData = data;
      expect(data).to.be.instanceOf(Array);
      expect(data).to.not.be.empty;
      expect(data[0]).to.include.keys('hostname', 'ip', 'mac', 'openPorts', 'osNmap');
      expect(data[0].openPorts).to.be.instanceOf(Array);
      expect(data[0].openPorts[0].port).to.exist;
      done();

    });
  });
  it('returns failure data for bad requests', function (done) {
    
    this.timeout(10000);
    nmap.osAndPortScan("127.0.0.", function (data) {
      
    },function(err){
      expect(err).to.be.a('string');
      done();
    });

  });

});