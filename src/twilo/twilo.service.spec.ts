import { Test, TestingModule } from '@nestjs/testing';
import { TwiloService } from './twilo.service';

describe('TwiloService', () => {
  let service: TwiloService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TwiloService],
    }).compile();

    service = module.get<TwiloService>(TwiloService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
