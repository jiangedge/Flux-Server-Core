package com.flux.client.protocol;

import com.flux.client.FluxClient;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

//序列号管理器
public class SeqManager {

    private final AtomicInteger sendSeq = new AtomicInteger(0);
    private final Map<String, Integer> receiveSeqMap = new ConcurrentHashMap<>();

    public int nextSendSeq() {
        int seq = sendSeq.getAndIncrement();
        if (seq < 0) {
            sendSeq.set(1);
            return 0;
        }
        return seq;
    }

    public boolean validateReceive(String sourceId, int receivedSeq) {
        Integer lastSeq = receiveSeqMap.get(sourceId);

        if (lastSeq == null) {
            receiveSeqMap.put(sourceId, receivedSeq);
            return true;
        }

        if (receivedSeq <= lastSeq) {
            FluxClient.LOGGER.warn("[Flux] REPLAY ATTACK! Source: {}, Expected: >{}, Got: {}",
                    sourceId, lastSeq, receivedSeq);
            return false;
        }

        receiveSeqMap.put(sourceId, receivedSeq);
        return true;
    }

    public void resetSource(String sourceId) {
        receiveSeqMap.remove(sourceId);
    }

    public void resetAll() {
        sendSeq.set(0);
        receiveSeqMap.clear();
    }
}
