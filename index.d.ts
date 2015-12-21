/// <reference path="typings/node/node.d.ts" />
import events = require('events');
export declare module nodenmap {
    interface host {
        hostname: string;
        ip: string;
        mac: any;
        openPorts: Array<port>;
        osNmap: string;
        scanTime?: number;
        error?: string;
    }
    interface port {
        port: number;
        service: string;
    }
    var nmapLocation: string;
    class NmapScan extends events.EventEmitter {
        command: string[];
        private nmapoutputXML;
        private timer;
        range: string[];
        arguments: string[];
        rawData: string;
        rawJSON: any;
        child: any;
        cancelled: boolean;
        scanTime: number;
        error: string;
        scanResults: host[];
        scanTimeout: number;
        constructor(range: any, inputArguments?: any);
        private startTimer();
        private stopTimer();
        private commandConstructor(range, additionalArguments?);
        private killChild();
        private initializeChildProcess();
        startScan(): void;
        cancelScan(): void;
        private scanComplete(results);
        private rawDataHandler(data);
        private convertRawJsonToScanResults(xmlInput, onFailure);
    }
    class QuickScan extends NmapScan {
        constructor(range: any);
    }
    class OsAndPortScan extends NmapScan {
        constructor(range: any);
    }
    class QueuedScan extends events.EventEmitter {
        private _queue;
        scanResults: host[];
        scanTime: number;
        currentScan: any;
        runActionOnError: boolean;
        saveErrorsToResults: boolean;
        singleScanTimeout: number;
        saveNotFoundToResults: boolean;
        constructor(scanClass: any, range: any, args: any[], action?: Function);
        private rangeFormatter(range);
        startRunScan(index?: number): void;
        startShiftScan(): void;
        pause(): void;
        resume(): void;
        next(iterations?: number): any;
        shift(iterations?: number): any;
        results(): host[];
        shiftResults(): host;
        index(): any;
        queue(newQueue?: any[]): any[];
        percentComplete(): number;
    }
    class QueuedNmapScan extends QueuedScan {
        constructor(range: any, additionalArguments?: any, actionFunction?: Function);
    }
    class QueuedQuickScan extends QueuedScan {
        constructor(range: any, actionFunction?: Function);
    }
    class QueuedOsAndPortScan extends QueuedScan {
        constructor(range: any, actionFunction?: Function);
    }
}
