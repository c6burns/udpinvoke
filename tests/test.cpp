#include "gtest/gtest.h"
#include "gmock/gmock.h"

using ::testing::StrictMock;
using ::testing::DefaultValue;
using ::testing::Return;


class Widget
{
public:
	virtual ~Widget() {}
	int DoWidgetStuff()
	{
		return 1;
	}
};


class MockWidget : public Widget
{
	MOCK_METHOD0(DoWidgetStuff, int());
};


template<class T> class WidgetHandle
{
public:
	int DoWidgetStuff()
	{
		return m_widgetImpl.DoWidgetStuff();
	}

private:
	T m_widgetImpl;
};


class BasicTest : public ::testing::Test
{
protected:
	void SetUp() override
	{
	}

	void TearDown() override
	{
	}
};



TEST_F(BasicTest, TestingTests)
{
	ASSERT_TRUE(1 == 1);
}

TEST_F(BasicTest, TestingMocks)
{
	WidgetHandle<Widget> realHandle;
	ASSERT_TRUE(realHandle.DoWidgetStuff() == 1);

	//DefaultValue<MockWidget>::DoWidgetStuff(2);
	//WidgetHandle<StrictMock<MockWidget>> strictHandle;
	////ON_CALL(StrictMock<MockWidget>, DoWidgetStuff()).WillByDefault(Return(2));
	//ASSERT_TRUE(WidgetHandle<Widget>.DoWidgetStuff() == 1);
}