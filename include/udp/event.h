#ifndef HB_EVENT_H
#define HB_EVENT_H

#define TCP_EV_MAX_SIZE 512
#define TCP_EV_PAD_SIZE (TCP_EV_MAX_SIZE) - (64 + 32 + 32 + 32 + 32)
#define TCP_EV_RECV_SIZE (TCP_EV_MAX_SIZE) - 32

#define HB_EVENT_FIELDS			\
	uint32_t id;				\
	uint32_t type;				\
	uint32_t context;			\
	uint32_t state;				\


enum tcp_event_type {
	TCP_EV_NONE = 0,
	TCP_EV_STATUS,
	TCP_EV_ERROR,
	TCP_EV_SEND,
	TCP_EV_RECV,
};

typedef struct {
	TCP_EV_FIELDS
	uint8_t pad[TCP_EV_PAD_SIZE];
} tcp_event_base_t;

// connection established
struct {
	TCP_EV_FIELDS
	struct sockaddr_storage *addr_local;
	struct sockaddr_storage *addr_peer;
} tcp_event_established_t;

// client status update
struct {
	TCP_EV_FIELDS
	int32_t state_prev;
} tcp_event_state_t;

// client recv bytes
struct {
	TCP_EV_FIELDS
	uint32_t data_len;
	uint8_t data[TCP_EV_RECV_SIZE];
} tcp_event_recv_t;

// client send bytes
struct {
	TCP_EV_FIELDS
	uint32_t data_len;
} tcp_event_send_t;


#endif