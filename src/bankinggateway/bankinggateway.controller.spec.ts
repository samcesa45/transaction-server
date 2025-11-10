import { Test, TestingModule } from '@nestjs/testing';
import { BankinggatewayController } from './bankinggateway.controller';

describe('BankinggatewayController', () => {
  let controller: BankinggatewayController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [BankinggatewayController],
    }).compile();

    controller = module.get<BankinggatewayController>(BankinggatewayController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
