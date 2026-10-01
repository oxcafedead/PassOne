export namespace ui {
	
	export class ClonePrep {
	    host: string;
	    fingerprint: string;
	    known: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ClonePrep(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.fingerprint = source["fingerprint"];
	        this.known = source["known"];
	    }
	}
	export class Picked {
	    path: string;
	    canceled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Picked(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.canceled = source["canceled"];
	    }
	}
	export class SettingsInfo {
	    dataDir: string;
	    storePath: string;
	    gitRemote: string;
	    pgpKeyFingerprint: string;
	    sshKeyId: string;
	    autoLockMinutes: number;
	    clipboardClearSeconds: number;
	    gitAuthorName: string;
	    gitAuthorEmail: string;
	    usernameSource: string;
	    hasPgp: boolean;
	    hasSsh: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SettingsInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dataDir = source["dataDir"];
	        this.storePath = source["storePath"];
	        this.gitRemote = source["gitRemote"];
	        this.pgpKeyFingerprint = source["pgpKeyFingerprint"];
	        this.sshKeyId = source["sshKeyId"];
	        this.autoLockMinutes = source["autoLockMinutes"];
	        this.clipboardClearSeconds = source["clipboardClearSeconds"];
	        this.gitAuthorName = source["gitAuthorName"];
	        this.gitAuthorEmail = source["gitAuthorEmail"];
	        this.usernameSource = source["usernameSource"];
	        this.hasPgp = source["hasPgp"];
	        this.hasSsh = source["hasSsh"];
	    }
	}
	export class UpdateInfo {
	    available: boolean;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.available = source["available"];
	        this.message = source["message"];
	    }
	}

}

