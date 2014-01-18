var chai = require('chai')
  , chain = require('../../lib/exchange/chain');


describe('exchange.chain', function() {
  
  it('should be named chain', function() {
    expect(chain(function(){}).name).to.equal('chain');
  });
  
  it('should throw if constructed without an issue callback', function() {
    expect(function() {
      chain();
    }).to.throw(TypeError, 'chain exchange requires an issue callback');
  });
  
});
