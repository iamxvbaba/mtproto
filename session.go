package mtproto

import (
	"encoding/json"
	"os"

	"github.com/ansel1/merry"
)

type Session struct {
	DcID        int32  `json:"dc_id"`
	AuthKey     []byte `json:"auth_key"`
	AuthKeyHash []byte `json:"auth_key_hash"`
	ServerSalt  int64  `json:"server_salt"`
	Addr        string `json:"addr"`
	sessionId   int64
}

func (s *Session) Save(path string) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return merry.Wrap(err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "\t")
	if err := encoder.Encode(s); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

func LoadSession(path string) (*Session, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, merry.New("no session data")
	}
	if err != nil {
		return nil, merry.Wrap(err)
	}
	defer f.Close()

	var sess Session
	if err := json.NewDecoder(f).Decode(&sess); err != nil {
		return nil, merry.Wrap(err)
	}
	return &sess, nil
}
