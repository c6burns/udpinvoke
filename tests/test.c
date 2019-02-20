int main(void)
{
}

//#include <stdio.h>
//
//#include "uv.h"
//
//#include "udp/log.h"
//#include "udp/thread.h"
//#include "udp/system.h"
//#include "udp/endpoint.h"
//
//
//int main(void)
//{
//	int ret = 0, state;
//	hb_system_t *hb_system = NULL;
//
//	if (!(hb_system = hb_system_new())) {
//		hb_log_uv_error(UV_ENOMEM);
//		goto fail;
//	}
//
//	if ((ret = hb_system_setup(hb_system, NULL, NULL))) {
//		hb_log_uv_error(ret);
//		goto fail;
//	}
//
//	if ((state = hb_system_get_state(hb_system)) < 0) {
//		hb_log_uv_error(ret);
//		goto fail;
//	}
//
//	hb_endpoint_t endpoint;
//	hb_endpoint_set_ip4(&endpoint, "0.0.0.0", 7777);
//
//	if ((ret = hb_system_start(hb_system))) {
//		hb_log_uv_error(ret);
//		goto fail;
//	}
//
//	int max_loops = 20;
//	int cur_loop = 0;
//	while (cur_loop < max_loops) {
//		int state = hb_system_get_state(hb_system);
//		if (state != HB_SYSTEM_STATE_STARTING && state != HB_SYSTEM_STATE_STARTED) break;
//
//		//hb_log_info("loop: %d", cur_loop);
//		if ((ret = hb_system_update(hb_system))) {
//			hb_log_uv_error(ret);
//			break;
//		}
//
//		cur_loop++;
//		if (cur_loop >= max_loops) break;
//
//		hb_thread_sleep_ms(200);
//	}
//
//	if ((ret = hb_system_stop(hb_system))) {
//		hb_log_uv_error(ret);
//		goto fail;
//	}
//
//	//getchar();
//	//fflush(stdin);
//
//	//getchar();
//	//fflush(stdin);
//
//	goto done;
//
//fail:
//
//done:
//	hb_thread_sleep_ms(200);
//	if (hb_system) {
//		hb_system_cleanup(hb_system);
//		hb_system_delete(&hb_system);
//	}
//
//	return 0;
//}