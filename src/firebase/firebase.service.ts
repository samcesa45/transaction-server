import { Injectable, OnModuleInit } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ServiceAccount } from 'firebase-admin';
@Injectable()
export class FirebaseService implements OnModuleInit {
  private app: admin.app.App;
  onModuleInit() {
    // const serviceAccount =
    //   require('../../notification-3dc63-firebase-adminsdk-fbsvc-63abf3b929.json') as ServiceAccount;

    // if (!admin.apps.length) {
    //   admin.initializeApp({
    //     credential: admin.credential.cert(serviceAccount),
    //   });
    // }
    // If already initialized, reuse the existing app
    if(admin.apps.length > 0) {
      this.app = admin.app();
      console.log('Firebase admin reused existing app');
      return;
    }
    //initialize firebase admin sdk
    this.app = admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey:process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g,'\n'),
      })
    });
    console.log('Firebase admin initialized')
  }
  getApp(): admin.app.App {
    return this.app
  }

  getMessage(): admin.messaging.Messaging {
    return admin.messaging(this.app)
  }
}
