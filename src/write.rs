use byteorder::{WriteBytesExt, BigEndian};
use std::io::{BufWriter, Write, Cursor};
use std::net::TcpStream;
use {Packet, QoS, Error, Result, MAX_PAYLOAD_SIZE, SubscribeTopic, SubscribeReturnCodes};

pub trait MqttWrite: WriteBytesExt {
    fn write_packet(&mut self, packet: &Packet) -> Result<()> {
        match packet {
            &Packet::Connect(ref connect) => {
                self.write_u8(0b00010000)?;
                let prot_name = connect.protocol.name();
                let mut len = 8 + prot_name.len() + connect.client_id.len();
                if let Some(ref last_will) = connect.last_will {
                    len += 4 + last_will.topic.len() + last_will.message.len();
                }
                if let Some(ref username) = connect.username {
                    len += 2 + username.len();
                }
                if let Some(ref password) = connect.password {
                    len += 2 + password.len();
                }
                self.write_remaining_length(len)?;
                self.write_mqtt_string(prot_name)?;
                self.write_u8(connect.protocol.level())?;
                let mut connect_flags = 0;
                if connect.clean_session {
                    connect_flags |= 0x02;
                }
                if let Some(ref last_will) = connect.last_will {
                    connect_flags |= 0x04;
                    connect_flags |= last_will.qos.to_u8() << 3;
                    if last_will.retain {
                        connect_flags |= 0x20;
                    }
                }
                if let Some(_) = connect.password {
                    connect_flags |= 0x40;
                }
                if let Some(_) = connect.username {
                    connect_flags |= 0x80;
                }

                self.write_u8(connect_flags)?;
                self.write_u16::<BigEndian>(connect.keep_alive)?;
                self.write_mqtt_string(connect.client_id.as_ref())?;

                if let Some(ref last_will) = connect.last_will {
                    self.write_mqtt_string(last_will.topic.as_ref())?;
                    self.write_mqtt_string(last_will.message.as_ref())?;
                }
                if let Some(ref username) = connect.username {
                    self.write_mqtt_string(username)?;
                }
                if let Some(ref password) = connect.password {
                    self.write_mqtt_string(password)?;
                }
                Ok(())
            },
            &Packet::Connack(ref connack) => {
                self.write_all(&[0x20, 0x02, connack.session_present as u8, connack.code.to_u8()])?;
                Ok(())
            },
            &Packet::Publish(ref publish) => {
                self.write_u8(0b00110000 | publish.retain as u8 | (publish.qos.to_u8() << 1) | ((publish.dup as u8) << 3))?;
                let mut len = publish.topic_name.len() + 2 + publish.payload.len();

                if publish.qos != QoS::AtMostOnce && None != publish.pid {
                    len += 2;
                }

                self.write_remaining_length(len)?;
                self.write_mqtt_string(publish.topic_name.as_str())?;
                if publish.qos != QoS::AtMostOnce {
                    if let Some(pid) = publish.pid {
                        self.write_u16::<BigEndian>(pid.0)?;
                    }
                }

                self.write_all(&publish.payload.as_ref())?;
                Ok(())
            },
            &Packet::Puback(ref pid) => {
                self.write_all(&[0x40, 0x02])?;
                self.write_u16::<BigEndian>(pid.0)?;
                Ok(())
            },
            &Packet::Pubrec(ref pid) => {
                self.write_all(&[0x50, 0x02])?;
                self.write_u16::<BigEndian>(pid.0)?;
                Ok(())
            },
            &Packet::Pubrel(ref pid) => {
                self.write_all(&[0x62, 0x02])?;
                self.write_u16::<BigEndian>(pid.0)?;
                Ok(())
            },
            &Packet::Pubcomp(ref pid) => {
                self.write_all(&[0x70, 0x02])?;
                self.write_u16::<BigEndian>(pid.0)?;
                Ok(())
            },
            &Packet::Subscribe(ref subscribe) => {
                self.write_all(&[0x82])?;
                let len = 2 + subscribe.topics.iter().fold(0, |s, ref t| s + t.topic_path.len() + 3);
                self.write_remaining_length(len)?;
                self.write_u16::<BigEndian>(subscribe.pid.0)?;
                for topic in subscribe.topics.as_ref() as &Vec<SubscribeTopic> {
                    self.write_mqtt_string(topic.topic_path.as_str())?;
                    self.write_u8(topic.qos.to_u8())?;
                }
                Ok(())
            },
            &Packet::Suback(ref suback) => {
                self.write_all(&[0x90])?;
                self.write_remaining_length(suback.return_codes.len() + 2)?;
                self.write_u16::<BigEndian>(suback.pid.0)?;
                let payload: Vec<u8> = suback.return_codes.iter().map({ |&code|
                    match code {
                        SubscribeReturnCodes::Success(qos) => qos.to_u8(),
                        SubscribeReturnCodes::Failure => 0x80
                    }
                }).collect();
                self.write_all(&payload)?;
                Ok(())
            },
            &Packet::Unsubscribe(ref unsubscribe) => {
                self.write_all(&[0xA2])?;
                let len = 2 + unsubscribe.topics.iter().fold(0, |s, ref topic| s + topic.len() + 2);
                self.write_remaining_length(len)?;
                self.write_u16::<BigEndian>(unsubscribe.pid.0)?;
                for topic in unsubscribe.topics.as_ref() as &Vec<String> {
                    self.write_mqtt_string(topic.as_str())?;
                }
                Ok(())
            },
            &Packet::Unsuback(ref pid) => {
                self.write_all(&[0xB0, 0x02])?;
                self.write_u16::<BigEndian>(pid.0)?;
                Ok(())
            },
            &Packet::Pingreq => {
                self.write_all(&[0xc0, 0])?;
                Ok(())
            },
            &Packet::Pingresp => {
                self.write_all(&[0xd0, 0])?;
                Ok(())
            },
            &Packet::Disconnect => {
                self.write_all(&[0xe0, 0])?;
                Ok(())
            }
        }
    }

    fn write_mqtt_string(&mut self, string: &str) -> Result<()> {
        self.write_u16::<BigEndian>(string.len() as u16)?;
        self.write_all(string.as_bytes())?;
        Ok(())
    }

    fn write_remaining_length(&mut self, len: usize) -> Result<()> {
        if len > MAX_PAYLOAD_SIZE {
            return Err(Error::PayloadTooLong);
        }

        let mut done = false;
        let mut x = len;

        while !done {
            let mut byte = (x % 128) as u8;
            x = x / 128;
            if x > 0 {
                byte = byte | 128;
            }
            self.write_u8(byte)?;
            done = x <= 0;
        }

        Ok(())
    }
}

impl MqttWrite for TcpStream {}
impl MqttWrite for Cursor<Vec<u8>> {}
impl<T: Write> MqttWrite for BufWriter<T> {}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::sync::Arc;
    use super::{MqttWrite};
    use super::super::{Protocol, LastWill, QoS, PacketIdentifier, ConnectReturnCode, SubscribeTopic};
    use super::super::mqtt::{
        Packet,
        Connect,
        Connack,
        Publish,
        Subscribe
    };

    #[test]
    fn write_packet_connect_mqtt_protocol_test() {
        let connect = Packet::Connect(Connect {
            protocol: Protocol::MQTT(4),
            keep_alive: 10,
            client_id: "test".to_owned(),
            clean_session: true,
            last_will: Some(LastWill {
                topic: "/a".to_owned(),
                message: "offline".to_owned(),
                retain: false,
                qos: QoS::AtLeastOnce
            }),
            username: Some("rust".to_owned()),
            password: Some("mq".to_owned())
        });

        let mut stream = Cursor::new(Vec::new());
        stream.write_packet(&connect).unwrap();

        assert_eq!(stream.get_ref().clone(), vec![0x10, 39,
            0x00, 0x04, 'M' as u8, 'Q' as u8, 'T' as u8, 'T' as u8,
            0x04,
            0b11001110, // +username, +password, -will retain, will qos=1, +last_will, +clean_session
            0x00, 0x0a, // 10 sec
            0x00, 0x04, 't' as u8, 'e' as u8, 's' as u8, 't' as u8, // client_id
            0x00, 0x02, '/' as u8, 'a' as u8, // will topic = '/a'
            0x00, 0x07, 'o' as u8, 'f' as u8, 'f' as u8, 'l' as u8, 'i' as u8, 'n' as u8, 'e' as u8, // will msg = 'offline'
            0x00, 0x04, 'r' as u8, 'u' as u8, 's' as u8, 't' as u8, // username = 'rust'
            0x00, 0x02, 'm' as u8, 'q' as u8 // password = 'mq'
        ]);
    }

    #[test]
    fn write_packet_connect_mqisdp_protocol_test() {
        let connect = Packet::Connect(Connect {
            protocol: Protocol::MQIsdp(3),
            keep_alive: 60,
            client_id: "test".to_owned(),
            clean_session: false,
            last_will: None,
            username: None,
            password: None
        });

        let mut stream = Cursor::new(Vec::new());
        stream.write_packet(&connect).unwrap();

        assert_eq!(stream.get_ref().clone(), vec![0x10, 18,
            0x00, 0x06, 'M' as u8, 'Q' as u8, 'I' as u8, 's' as u8, 'd' as u8, 'p' as u8,
            0x03,
            0b00000000, // -username, -password, -will retain, will qos=0, -last_will, -clean_session
            0x00, 0x3c, // 60 sec
            0x00, 0x04, 't' as u8, 'e' as u8, 's' as u8, 't' as u8 // client_id
        ]);
    }

    #[test]
    fn write_packet_connack_test() {
        let connack = Packet::Connack(Connack {
            session_present: true,
            code: ConnectReturnCode::Accepted
        });

        let mut stream = Cursor::new(Vec::new());
        stream.write_packet(&connack).unwrap();

        assert_eq!(stream.get_ref().clone(), vec![0b00100000, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn write_packet_publish_at_least_once_test() {
        let publish = Packet::Publish(Publish {
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            topic_name: "a/b".to_owned(),
            pid: Some(PacketIdentifier(10)),
            payload: Arc::new(vec![0xF1, 0xF2, 0xF3, 0xF4])
        });

        let mut stream = Cursor::new(Vec::new());
        stream.write_packet(&publish).unwrap();

        assert_eq!(stream.get_ref().clone(), vec![0b00110010, 11, 0x00, 0x03, 'a' as u8, '/' as u8, 'b' as u8, 0x00, 0x0a, 0xF1, 0xF2, 0xF3, 0xF4]);
    }

    #[test]
    fn write_packet_publish_at_most_once_test() {
        let publish = Packet::Publish(Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic_name: "a/b".to_owned(),
            pid: None,
            payload: Arc::new(vec![0xE1, 0xE2, 0xE3, 0xE4])
        });

        let mut stream = Cursor::new(Vec::new());
        stream.write_packet(&publish).unwrap();

        assert_eq!(stream.get_ref().clone(), vec![0b00110000, 9, 0x00, 0x03, 'a' as u8, '/' as u8, 'b' as u8, 0xE1, 0xE2, 0xE3, 0xE4]);
    }

    #[test]
    fn write_packet_subscribe_test() {
        let subscribe = Packet::Subscribe(Subscribe {
            pid: PacketIdentifier(260),
            topics: vec![
                SubscribeTopic { topic_path: "a/+".to_owned(), qos: QoS::AtMostOnce },
                SubscribeTopic { topic_path: "#".to_owned(), qos: QoS::AtLeastOnce },
                SubscribeTopic { topic_path: "a/b/c".to_owned(), qos: QoS::ExactlyOnce }
            ]
        });

        let mut stream = Cursor::new(Vec::new());
        stream.write_packet(&subscribe).unwrap();

        assert_eq!(stream.get_ref().clone(),vec![0b10000010, 20,
            0x01, 0x04, // pid = 260
            0x00, 0x03, 'a' as u8, '/' as u8, '+' as u8, // topic filter = 'a/+'
            0x00, // qos = 0
            0x00, 0x01, '#' as u8, // topic filter = '#'
            0x01, // qos = 1
            0x00, 0x05, 'a' as u8, '/' as u8, 'b' as u8, '/' as u8, 'c' as u8, // topic filter = 'a/b/c'
            0x02 // qos = 2
        ]);
    }
}
