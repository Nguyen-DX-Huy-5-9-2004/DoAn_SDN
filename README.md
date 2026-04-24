# Technical Report: DoAn_SDN Project

## Overview
The DoAn_SDN project integrates Software-Defined Networking (SDN) with a sophisticated real-time Intrusion Detection System (IDS). This document serves as a comprehensive guide detailing the system architecture, data collection methodologies, AI model implementations, and system design principles. It aims to provide insights into the decisions made throughout the development process, demonstrating a deep understanding in Networking, Data Science, Deep Learning, and System Design.

## System Architecture
The architecture consists of three core components:
1. **Data Collection Layer**  
2. **AI Model Layer**  
3. **Real-Time IDS Layer**  

### 1. Data Collection Layer
The data collection layer is responsible for gathering network traffic data from various sources. This includes:
- **Packet Capturing:** Using tools like Wireshark or TCPDUMP to capture real-time traffic.
- **Flow Monitoring:** Utilizing NetFlow or sFlow for monitoring and analyzing traffic flows.
- **Logging:** Implementing logs that capture significant events in the network.

#### Implementation Example:
```python
import pyshark

def capture_packets(interface):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(packet_count=10)
    for packet in capture:
        print(packet)
```

### 2. AI Model Layer
The AI models are designed to analyze the collected data for intrusions. The models leverage:
- **Supervised Learning:** Using labeled datasets for training classifiers (e.g., Random Forest, SVM).
- **Deep Learning:** Implementing Neural Networks for feature extraction and anomaly detection.

#### Example Code Snippet:
```python
from sklearn.ensemble import RandomForestClassifier

# Assume X_train and y_train are pre-processed features and labels
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)
```

#### Model Evaluation:
Evaluate model performance using metrics such as accuracy, precision, and recall.

### 3. Real-Time IDS Layer
The real-time IDS integrates with the system to provide alerts on suspicious activities. Key features include:
- **Alert System:** Sending notifications based on detection.
- **Dashboard:** A visual interface for monitoring real-time data processing.

#### Implementation Example:
```python
import time

def alert_user(alert_message):
    print(f'ALERT: {alert_message}') 

while True:
    if detect_intrusion():
        alert_user('Intrusion detected!')
    time.sleep(5)
```

## Problem-Solving Approach
Throughout the project, various challenges were encountered and resolved through:
- **Iterative Development:** Constantly refining models based on feedback and performance metrics.
- **Cross-Disciplinary Collaboration:** Collaborating with networking and security experts to enhance system reliability.

## Conclusion
The DoAn_SDN project presents a robust integration of SDN technologies with AI-enhanced security mechanisms. This document serves not only as documentation but also as a reference for future enhancements and a guide for other engineers working on similar solutions.