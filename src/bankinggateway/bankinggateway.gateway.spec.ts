import { Test, TestingModule } from '@nestjs/testing';
import { BankinggatewayGateway } from './bankinggateway.gateway';

describe('BankinggatewayGateway', () => {
  let gateway: BankinggatewayGateway;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [BankinggatewayGateway],
    }).compile();

    gateway = module.get<BankinggatewayGateway>(BankinggatewayGateway);
  });

  it('should be defined', () => {
    expect(gateway).toBeDefined();
  });
});
