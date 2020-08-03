package main

import "github.com/iamxvbaba/mtproto"

func main() {
	mt := mtproto.NewMTProto(mtproto.MTParams{
		AppConfig:  nil,
		ConnDialer: nil,
		Session:    &mtproto.Session{
			DcID:        0,
			AuthKey:     nil,
			AuthKeyHash: nil,
			ServerSalt:  0,
			Addr:        "127.0.0.1:7743",
		},
	})
	mt.Connect()
}
