package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/IBM/sarama"
	"github.com/cloudflare/circl/abe/cpabe/tkn20"
	"github.com/lovoo/goka"
	"github.com/lovoo/goka/codec"
)

type Message struct {
	Policy        string `json:"policy"`
	MessageBase64 string `json:"message"`
}

var (
	brokers             = []string{"localhost:9092"}
	topic   goka.Stream = "input-topic"
	group   goka.Group  = "output-group"

	tmc       *goka.TopicManagerConfig
	pkstring  = "040604000200153ccd12eb9a48c25e573d0d0c80aad3c86e7d72872edbe44c3ef133ded1b7a28933170902bb634afb1d4261736ffc030d374a7a29dede6f90000dfa54e4311d38789fb561d7f9871c6b314bafc5c4c89c91ebe93dcd6c5dbd0066cbd60615a30408d58961fbc42ccb460863290483e2ee4a6ef9553e283291cb1a1989190ef9b67562b66013792544c543dcf2ffcb7b0b6aee714f211587cde039fb5095b02dff4d072b0ad37cc88cbb686e66ca8e43c2d57d56792ce865add87cfbf719aa900e27cc15bbe2d407a1f2e341f5faa8cb3d786e72e841ef379caaf5653b958b41e4e006eac3d964fe52d6f34a8343dd7504b701693079bba9a84726b6f854b140d2c2c27f8c9f4a8eae42b0f8b7dcf611a21fecdb363af1d6f6eb421b496de22114b6aa7df5baab8d115e65ecc89f42aaacb60d5c97b8905efcbebb8d4e5451f59975c68e32e1672cdbf73e95e8f4ed2f088253675f20c767269c4620c3f9a8b6e57b68233f607547037f2a7ebb2832048b6e0ff08e26240ea563ebb2110483c6195db81e4a940eba93c2fd62d27eb5f2358f051a6d18541860e8791cc7b506f61ddbe41b752466ca880a1fe47206dc620db22fa9c0f891dc8d68fd120c429b432d2938ecc715718271765e29df5eba72a9d6f28ef8e8a761008fe8e1e813feb5143fecdc70fb464a9a4a68f5899499440bba15fb0fb3391daab3088f406caeaa543d710002f9838d14a5d94f13f5ade31533dcfb4ef2f9240fbbebd65a4c188071da7faec38cee25a480c60c3af8288e582ea84e4ebb92c8ad07c73fbf49ff7717e4f2da572abbd5bcba5de779ab4a352e5e171913fcfaf621473716354474b30c31604ddcf737c4d4086ef6094a22d10bb152f9068086ba900ace9dd3de8d2b1115a53c28571893299553635fb934d002292147dad23f3c99e7638b3a99a52b00b8007ba552baeb975d17f147a6d6ca59c67fb786fcfcd350e18289d84e44922b335aa775a6975f7239b39f5e8a2ae005e2fcfe2462ae78d15e06b9bef4c9831a0f870c2919f857631dc6a20ca0d839a96a7c33281cc522f6b9861f934a2cb80d5da804caa942e72ad2b587019b7d4b124aa359df59d65cc1ec00b4fbfac6beeece9405eed8816c68bcee56542e861e0e33b673ed40e0ca639b25bd5e9e73aebd5e50d5cd83f39624e27c90b212949092644de1c2efa04b5da8fd04087d7d1510dee9727fe15018c7189752b0d38d781813b85f582c36058afd3d2101e97ac3270fbf00bf622cec621837f72b3f568c012ca1356f2625ecb95bd5ab1b9090a282e79a3a133ff9da3f9a360256d7ce626ca07eb7628e808516211121ab631cc503f5dae00cbc90f9bf041a9bb44149e0b2a1511238747249f4e7cbc92f81425dd8c1fd5dbf250a4c4159f15f099715350ce2dbca9fde5ce712a81eedf6e24424c76672d57306cf768e8cf56fc24eb1f1c65a976a166ba74bbc28c32cb1faefe0022dc44a83e350d135f339195a374a60c6238b18ef425fd4e8622997c3e3be9abb3b02e1a3ab3f5e1b01191016443472193944237b6d6c7756b3eeae23e677a4e0ed5640e4d6c408b2bb3c65d86a98ddb0c45385b265439766e943115057159015fba17e6e7cf6773141a891ca4ed53a15ad9f32a8132e7fecfb4ad3dd894340c5958c61a856a1a1f8e9fe5ee1db6ae710e51f92047d36f75ebe880ae8e5a61b73668efc6069122fa7c5b564c724e9e91bee37f98e1bb15c44c5c80185a666950a6084a7904a15690bb319a1ed9995856e928471dbbb746adc65465a922170430e3204e34435dbb5d34838f2268fd6a00bed717cfab8960f0dca4f6f0b1d3409c0eccbc0cbb0856735b87848c287bd1c50b478e0cf4ad88c32176c6a71d36b6c19aebdc92e79577ad8ca8268e735a2d538ba19bcef6f773a715996e50d9c9aaad0ee2a78bf4aae5783783d0be4de705e0a5dd9a5e238ed2ecc76f48ca71cbfeefc41bd401023a990e9c47db743eb994d431513ffdc8e2823e2502402cdb62ff016b952e33bf9e1146d60affb84f2213358dd1a9f598c5211ee744e27f154d4dd0ff3eb2718df5ac6db4112ce68f9de350f83db54aaea710c2bde92197a5360bb8d582b8260b5203d091aac2ffbfdb3573f92b37a7a59556d8862d997dac99f4a44020300020017d4c8f8130e71318ebbd561dc3fe517d62189771352440f66a64a1c3d917ba451b7482b71c8fa23a23165211362d962160ef77302ff5bacc015ca63e28057c4777349e4b91aef206b1bbc1771d0c85dd89a15b6a182bf99bcbf5c30849e56850c6ce38cf288b94d3c4103fdbbe11cd546f55e5230c695430cfe13b1539965a8b0fb3f80da0feaf13e5fac3abe39a53307ff551c257dfe17df7b99c8721390a86f913bcfa811716b9488dc16e2f6c1b4ffaaf4b28b592d417fb54a61f49b12500ff32ca7af9fec436cd5db3c6874e3f2011b7c058e5e2ea81540a37871018a5a20f7a13737b910f1f71d293bdef819c509a49b512a97646cbf4d0dd7620f2f1e772d9dd38e2c3bbf964205d9a3f1fed32b6a51a9577c17cbd7dac531800406b40009f1033c1dca3c7facb61476c3a7502fe60667ffdc2963a95ad3355fc8893b67e3619b10ae426b9bd9fa5d1ecfccea161572511b292bbd61a81cd2f2788214fa9d96295f9371b1bba8c4d8acd0b5487d280c161815669e0777125a1114113519bc4fd2ed11f9d2c69f6c59489f0bb0c25be02d5aa7f1475cf83eb25b6b3113caf9a5d96188101b6a3326b490030c2c0b60dd0626e87d559d9b4ee745ad2c8c3985e72a8aaa2ffa100c65d52dad3cdae21bf345bc4c26d4108dc2aa8198bf970cf71778665e673fc59054666d600da5c5752f02bba4520acf8966c0ef0614a010b0ca2e9d953570f5a20620a38f9cd503fc18a26f0b10784031dc4b2fddcb1d3eecbfce899c7f2f3959760c1232d4d0e548870660b6bfc308329d1bc04376f88404020001000d4efbf46bf65c04959bcd3507711d4ef99592fbabcbc8eaa4100a04eb34db7c16f8983e79a2d0227c59674f21ed80f00ca55ca813f261241b80253c46a49de8586d6722470afef4f300c769532ed219c9183a6a2fa81a6d86c5268d4adbade606e75a7807fe4c5da8365af9c57fd047a77b5a622b6747ea984089ae6a8f2d545cb2991feee1d65dd47f67eeb76915b80fe167641ed0f6d644fd468003d48ab5ae563a7bdf5a63daa58c37aca46f8f5cff5b1f46beccfed2d148d73afd214c45102de239837a27c220595c85ed75ad5672bc2ccabe1a8c4fc40d4ff6fa7ef9fcf4edba2c0929b616fd65dd306c15b11b0d655769c87d2b65be9bee9d9fcc5b36e0986e5cfe938ec07f5dc566ea72215ad545003e47127f3f7351e4988332ae32073f609ee12b111ce615d9510763eb8958fbb488af31df619316c9cc2b7a314b4b8d55389392f7176bea35bf7ed7eb35078a695ced0186f9f9fc1059e75b1249f8b8259567d58e4f940a7b094b16b0c7cde8c07556ae76dd2bb72199a22250aa02ca8e6041f2929a56a3531a6f0a4cf59db243a00a432181cc8e6cf15b7e175f178feeddb514faafe71f18ebcd232d1218ead9e13c8656a3943bc2d3f04725b4417bdd67e401a2d0dae9145de2859336380fa628a7536e410311fb55811cf1e103497b5f8a55f1b7981ab5986364e55df6f7cef4ac4dfaf1d8efe8db903e792b650592886b2490eb0caf3c4f6c482d1308e25d408dd68c5cec8ea53dc4e825e1f2397c6ba6fafc26340258d0cee9996bcc7d35f4f085aad00aa1812731d6e5e5156bc43417b7e1f58853f0d7f75da4f8adf955a2a1c818358ad17e0fdd66acd7e6d49fd4818b381f36da9876ce7ce1ea026c628531bf46188cfcc76ef347aca90e55ec8067a81e660c74f3db0e66d87ea252aed3559676ec410510d6caa973a90c1abde1aeb2fafc06c82d76e4ba33972227ef2034c4f9d109a29123af1e7e18291592d7be98edffb839d3e61837dcdc0cd9645948b4060af8f2afd90ea6113da732bb31133cb03b4b570ad40c58b3d6b0afa5deea6e3e4e5203aff82380db1913941693b98bb50009e009ff4e42832e4575c7b82343f1d6336ff95d6bbf0499fe62471b14b390b5d6356f86357d325806626519416d45117c09619a8bba0d1c71fbe97c19bd6f98ae8b48c37c5bbabfdc3838fbd44bd9166660395f1012e899080232d90e31ee031e7be736b49fba4d47fe37dc9e52458073d8530a955eb7b81c3c79c3cf018c06a22ebc791111560015dac31c3c558eec974ac6d3d8a2138658e9c6a8596c64d3fc5ea728b4ce392c05d8eb307904a5247e8ea6bb0a6fbe500d64ca1a1b8f43dc4e627aa9f9a11a8ef833e2d7fc6db6472aebe8228019f61f85a1528add2bfca16ce8e9c81de0324106df04ba6f72d38ef590613c1d2dbd371bb1cae427bc4828aed62a70e2c78e31f2c47f6b648e26c00ebc5b7b6244f95e08e93c24035e5a0d4ca28fbca3bf0f4b1640b8499b9dee251d1b7bb1c0b16ecc86cbb509c3a116648e9f78c2d73f604c0ad7143c66e0433ac45b1b346e4b589578406d9f25ce8a291c6f1e6b26ce6979e95466c7407357218573afa487ce07eb" // your public key string
	mskstring = "c4000300020016ffdc3813aca94db83a2630bfb0107bb87468cae0b4488b50311b47b456cbae00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000263281d7ccf7ec852589948bdb25d8dbf0ab53f0d23a06ebaef80e3b08294b8d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000104010400020005dff6dc42f772059fcedf4f32193935ba2cd53b102c0f9863e9183acb69606139629d85c97cff6a97ebdc6afb2f0f9677946793ff180cfc7cb061f32476613f50b4204a14c5efa018bf6071980248b9a294c66328d97ed6b20256bd33a1aa200154d881561d5eccec77c51ef97670608a923aff0a991aa126c4d717fc7945d467dd5d0eddd61ecd68744f26a791c4a1e0d8e539949fd0a4ac06666f86d24a941010480a6e1132dee5241f73b2945854dc6250403554e3f2ad1ea5f85e332f6622828dd523e539d0a6087d3be8db911a83f6439e22fa9982ceca733ff556e82623c0af50ef5d40e50c42d31c75f9a6fefa242e7a60a627d6170a19cff005d5f70401040002002f4618970da1899ca76fb54f2b5567844db1a6d506c3cfd2131eb720a4b40a4551eea27b880ce4e2bb0ee3f7c72051b4c939e4d53987138ad4cc2730e3028dc44650fdbfa914c67eeba3f9ae239dd8ab22982d01d0ea20fb7d8bdccd4e7ac5c64c6cecb7d5454f94ec88d3d88672f5eee4b141c0703c27f885756ec0e80711fc6277d4faa9d2b8d00572a9b3726b215e8e37b4f57cc722c2a983fa59de1b1eaf6d3cb9579e8bf12a7f4ee7652a45f3ab4925e1b070712913a3d1e4833f8d42b454f48bd6db3ce371cec3980a6ff630640dd6311f76f655d34a3ef00b0fbac1c4189b4a08137e44f8ab31ccb62c9ec62566ccb72af23039510b4b14a016cd27440401040002002aeb2f3f651a14425e06f8aa88093e6a5499d6ac579a3feb906dda3c066b3ca31ca42a0eb072d2a04786e94a85e449a367aab86f24370634d30562e82fdd32572193d358288fcceb80229f979a18252d93166f1aed5b1f49bb469b59f837680900f96058f6f7d140b8ad6e691f7ce8aeeda4e5b5859f3e7f7df6b08f86d037f100d2b5dafbd680393290ee656df7caf616c9243101d61a16c6acea8a812e8df404a1bd1edd38481edadcddd542d1187a7899ccc2145163561dcd4639b1c9b708555cc633dfc6c729342cb877fb0530a120bff2080aa7542d0a1e17628e77b7f95d90b6cbcb43c5231beaeafa0d9ad0fcc5f798d5ecd8826c235b6731b8e19bc684000400010032910c4cd573130e14fdd8dd1253fb76759f169239d0351dc98453423ae8faef52ce396400aeda4db45b07c6ffa2a96badadd87cef50942a78294c9132e2d68753ed7af2c3ee7a8293609395ec1e84b513081868c6e5995a04857328eceaa21b5530a8ade3f5ad590e8e3ee3d070b60602f6fa7e84cdf8d4ba4c3016da6f7211100074bd8d35afe2d8e49083439ab0fff8b3"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     // your master secret key string
	pk        tkn20.PublicKey
	msk       tkn20.SystemSecretKey
)

func init() {
	tmc = goka.NewTopicManagerConfig()
	tmc.Table.Replication = 1
	tmc.Stream.Replication = 1
}
func main() {
	consumerTopic := flag.String("consumer", "", "Consumer")
	flag.Parse()

	if *consumerTopic == "" {
		fmt.Println("Consumer topic is required.")
		return
	}
	{
		config := sarama.NewConfig()
		config.Producer.Return.Successes = true
		config.Producer.RequiredAcks = sarama.WaitForLocal       // Wait for only the leader to acknowledge the message
		config.Producer.Compression = sarama.CompressionSnappy   // Compress messages
		config.Producer.Flush.Frequency = 500 * time.Millisecond // Flush batches every 500ms

		// Initialize Kafka producer
		producer, err := sarama.NewSyncProducer([]string{"localhost:9092"}, config)
		if err != nil {
			log.Fatalf("Failed to create producer: %v", err)
		}
		defer producer.Close()

		// Create a Message object
		message := Message{
			Policy:        "Topic: Medical",
			MessageBase64: base64.StdEncoding.EncodeToString([]byte("ranny")),
		}

		// Marshal Message object to JSON
		jsonMessage, err := json.Marshal(message)
		if err != nil {
			log.Fatalf("Failed to marshal message to JSON: %v", err)
		}

		// Produce message to Kafka topic
		msg := &sarama.ProducerMessage{
			Topic: "input-topic",
			Value: sarama.StringEncoder(jsonMessage),
		}
		partition, offset, err := producer.SendMessage(msg)
		if err != nil {
			log.Fatalf("Failed to produce message: %v", err)
		}

		log.Printf("Produced message: %v, to topic: %s, partition: %d, offset: %d", msg.Value, msg.Topic, partition, offset)

	}

	topic := goka.Stream(*consumerTopic)
	brokers := []string{"localhost:9092"}

	pkdec, _ := hex.DecodeString(pkstring)
	mskdec, _ := hex.DecodeString(mskstring)
	_ = pk.UnmarshalBinary(pkdec)
	_ = msk.UnmarshalBinary(mskdec)
	pk_byte, _ := pk.MarshalBinary()
	log.Printf("PK:#%x", pk_byte)
	msk_byte, _ := msk.MarshalBinary()
	log.Printf("MSK:#%x", msk_byte)

	g := goka.DefineGroup(group,
		goka.Input(topic, new(codec.String), handle),
		goka.Persist(new(codec.String)),
	)
	// Define and initialize Goka processor
	p, err := goka.NewProcessor(brokers,
		g,
		goka.WithTopicManagerBuilder(goka.TopicManagerBuilderWithTopicManagerConfig(tmc)),
		goka.WithConsumerGroupBuilder(goka.DefaultConsumerGroupBuilder),
	)
	if err != nil {
		log.Fatalf("error creating processor: %v", err)
	}
	ctx, _ := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err = p.Run(ctx); err != nil {
			log.Printf("error running processor: %v", err)
		}
	}()

	// Wait for termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

// Define the message handler function
func handle(ctx goka.Context, msg interface{}) {
	var message Message
	json.Unmarshal(msg.([]byte), &message)

	policy := tkn20.Policy{}
	err := policy.FromString(message.Policy)
	if err != nil {
		log.Printf("Error parsing policy: %v", err)
		return
	}
	decoded, _ := base64.StdEncoding.DecodeString(message.MessageBase64)
	ciphertext, _ := pk.Encrypt(rand.Reader, policy, decoded)
	log.Printf("Ciphertext: %x\n", ciphertext)
	policymap := policy.ExtractAttributeValuePairs()
	newtopic := policymap["Topic"][0]

	encoded := base64.URLEncoding.EncodeToString(ciphertext)
	outgoing := Message{
		Policy:        message.Policy,
		MessageBase64: encoded,
	}
	jsonData, err := json.Marshal(outgoing)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	// Publish message to new topic
	ctx.Emit(goka.Stream(newtopic), newtopic+"1", jsonData)
}
